// Package hammer implements sentinel-hammer: active containment & isolation
// with graduated responses (WARN, THROTTLE, SEVER, QUARANTINE) and hard PID
// safety rails.
//
// In userland / PRoot environments:
//   - SEVER prioritizes revoking active session tokens and aborting tracked
//     bridge/shim streams first; netlink SOCK_DESTROY is capability-gated
//     (CAP_NET_ADMIN) and falls back cleanly when unprivileged.
//   - QUARANTINE freezes the offending PID (or process group when verified safe
//     against protected ancestors) via SIGSTOP, handling ESRCH/EPERM cleanly.
package hammer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/policy"
)

// SessionSeverer is implemented by sentinel-bridge to revoke session tokens
// and close tracked streaming connections immediately on SEVER.
type SessionSeverer interface {
	SeverSession(session string) int
}

// Request describes a containment action requested by sentinel-core.
type Request struct {
	Mode       policy.Mode
	Action     policy.Action
	Session    string
	PID        int
	Group      bool // attempt -pgid freeze when safe
	RemoteIP   string
	RemotePort int
	RuleIDs    []string
	Reason     string
}

// Result reports what sentinel-hammer actually applied.
type Result struct {
	Action      string `json:"action"`
	Effective   string `json:"effective"`
	Simulated   bool   `json:"simulated"`
	StreamsCut  int    `json:"streams_cut,omitempty"`
	SockDestroy string `json:"sock_destroy,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Err         error  `json:"-"`
}

// QuarantineRecord tracks a currently frozen PID/PGID.
type QuarantineRecord struct {
	PID      int       `json:"pid"`
	PGID     int       `json:"pgid,omitempty"`
	Group    bool      `json:"group,omitempty"`
	Session  string    `json:"session,omitempty"`
	RuleIDs  []string  `json:"rule_ids,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	FrozenAt time.Time `json:"frozen_at"`
}

type Hammer struct {
	ProcRoot   string // defaults to "/proc"
	StatusPath string // defaults to "/proc/self/status"
	Severer    SessionSeverer
	ThrottleTT time.Duration // default 15s

	mu          sync.Mutex
	protected   map[int]bool
	quarantined map[int]QuarantineRecord
	throttled   map[string]time.Time
}

func New(severer SessionSeverer, protectedPIDs ...int) *Hammer {
	h := &Hammer{
		ProcRoot:    "/proc",
		StatusPath:  "/proc/self/status",
		Severer:     severer,
		ThrottleTT:  15 * time.Second,
		protected:   map[int]bool{0: true, 1: true, os.Getpid(): true, os.Getppid(): true},
		quarantined: map[int]QuarantineRecord{},
		throttled:   map[string]time.Time{},
	}
	for _, p := range protectedPIDs {
		if p > 0 {
			h.protected[p] = true
		}
	}
	// Protect our entire ancestor chain up to PID 1.
	for _, anc := range h.ancestorPIDs(os.Getpid()) {
		h.protected[anc] = true
	}
	return h
}

// IsProtectedPID reports whether signaling pid is forbidden by hard safety rails.
func (h *Hammer) IsProtectedPID(pid int) bool {
	if pid <= 1 {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.protected[pid] {
		return true
	}
	return false
}

// Execute applies (or simulates in observe mode) the requested containment action.
func (h *Hammer) Execute(req Request) Result {
	res := Result{Action: req.Action.String()}
	if req.Action <= policy.Warn {
		res.Effective = req.Action.String()
		return res
	}
	if req.Mode == policy.Observe {
		res.Effective = policy.Warn.String()
		res.Simulated = true
		res.Detail = "observe mode dry-run; no signal or sever applied"
		return res
	}

	switch req.Action {
	case policy.Throttle:
		key := req.Session
		if key == "" && req.PID > 0 {
			key = fmt.Sprintf("pid:%d", req.PID)
		}
		if key != "" {
			tt := h.ThrottleTT
			if tt <= 0 {
				tt = 15 * time.Second
			}
			h.mu.Lock()
			h.throttled[key] = time.Now().Add(tt)
			h.mu.Unlock()
		}
		res.Effective = policy.Throttle.String()
		res.Detail = "session/pid rate-limited"
		return res

	case policy.Block:
		res.Effective = policy.Block.String()
		return res

	case policy.Sever:
		res.Effective = policy.Sever.String()
		// 1. Primary userland path first: revoke tokens & drop tracked streams.
		if h.Severer != nil && req.Session != "" {
			res.StreamsCut = h.Severer.SeverSession(req.Session)
		}
		// 2. Optional privileged path: CAP_NET_ADMIN SOCK_DESTROY fallback.
		if req.RemoteIP != "" && req.RemotePort > 0 {
			ok, note := trySockDestroy(h.StatusPath, req.RemoteIP, req.RemotePort)
			res.SockDestroy = note
			if ok {
				res.Detail = fmt.Sprintf("severed %d stream(s); socket destroyed", res.StreamsCut)
			} else {
				res.Detail = fmt.Sprintf("severed %d stream(s); %s", res.StreamsCut, note)
			}
		} else {
			res.Detail = fmt.Sprintf("severed %d stream(s) for session %q", res.StreamsCut, req.Session)
		}
		return res

	case policy.Quarantine:
		// Also sever session streams if known.
		if h.Severer != nil && req.Session != "" {
			res.StreamsCut = h.Severer.SeverSession(req.Session)
		}
		if req.PID == 0 && req.Session != "" {
			res.Effective = policy.Block.String()
			res.Detail = "no target PID available; downgraded quarantine to session block"
			return res
		}
		rec, err := h.freeze(req)
		if err != nil {
			res.Effective = policy.Warn.String()
			res.Err = err
			res.Detail = err.Error()
			return res
		}
		res.Effective = policy.Quarantine.String()
		if rec.Group {
			res.Detail = fmt.Sprintf("froze process group -%d (pid %d) via SIGSTOP", rec.PGID, rec.PID)
		} else {
			res.Detail = fmt.Sprintf("froze pid %d via SIGSTOP", rec.PID)
		}
		return res
	}
	res.Effective = req.Action.String()
	return res
}

// IsThrottled reports whether key (session or "pid:<n>") is currently in backoff.
func (h *Hammer) IsThrottled(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	exp, ok := h.throttled[key]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(h.throttled, key)
		return false
	}
	return true
}

func (h *Hammer) freeze(req Request) (QuarantineRecord, error) {
	if h.IsProtectedPID(req.PID) {
		return QuarantineRecord{}, fmt.Errorf("safety rail refused to quarantine protected pid %d", req.PID)
	}
	signalTarget := req.PID
	rec := QuarantineRecord{
		PID:      req.PID,
		Session:  req.Session,
		RuleIDs:  append([]string(nil), req.RuleIDs...),
		Reason:   req.Reason,
		FrozenAt: time.Now().UTC(),
	}
	if req.Group {
		if pgid, err := syscall.Getpgid(req.PID); err == nil && pgid > 1 && h.isPGIDSafe(pgid) {
			signalTarget = -pgid
			rec.PGID = pgid
			rec.Group = true
		}
	}

	if err := syscall.Kill(signalTarget, syscall.SIGSTOP); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return QuarantineRecord{}, fmt.Errorf("pid %d already exited before SIGSTOP (ESRCH)", req.PID)
		}
		if errors.Is(err, syscall.EPERM) {
			return QuarantineRecord{}, fmt.Errorf("permission denied sending SIGSTOP to %d (EPERM)", signalTarget)
		}
		return QuarantineRecord{}, fmt.Errorf("SIGSTOP %d failed: %w", signalTarget, err)
	}

	h.mu.Lock()
	h.quarantined[req.PID] = rec
	h.mu.Unlock()
	return rec, nil
}

// Unfreeze resumes a quarantined PID (or PGID) via SIGCONT.
func (h *Hammer) Unfreeze(pid int) error {
	if h.IsProtectedPID(pid) {
		return fmt.Errorf("safety rail refused to signal protected pid %d", pid)
	}
	h.mu.Lock()
	rec, ok := h.quarantined[pid]
	h.mu.Unlock()

	target := pid
	if ok && rec.Group && rec.PGID > 1 && h.isPGIDSafe(rec.PGID) {
		target = -rec.PGID
	}
	err := syscall.Kill(target, syscall.SIGCONT)
	h.mu.Lock()
	delete(h.quarantined, pid)
	h.mu.Unlock()
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("SIGCONT %d failed: %w", target, err)
	}
	return nil
}

// Kill terminates a quarantined or offending PID (SIGTERM, or SIGKILL if force).
func (h *Hammer) Kill(pid int, force bool) error {
	if h.IsProtectedPID(pid) {
		return fmt.Errorf("safety rail refused to kill protected pid %d", pid)
	}
	h.mu.Lock()
	rec, ok := h.quarantined[pid]
	h.mu.Unlock()

	target := pid
	if ok && rec.Group && rec.PGID > 1 && h.isPGIDSafe(rec.PGID) {
		target = -rec.PGID
	}
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	// If stopped, SIGCONT after SIGTERM ensures non-SIGKILL termination is delivered.
	err := syscall.Kill(target, sig)
	if err == nil && !force {
		_ = syscall.Kill(target, syscall.SIGCONT)
	}
	h.mu.Lock()
	delete(h.quarantined, pid)
	h.mu.Unlock()
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill %d failed: %w", target, err)
	}
	return nil
}

// Quarantined returns all currently quarantined processes sorted by PID.
func (h *Hammer) Quarantined() []QuarantineRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]QuarantineRecord, 0, len(h.quarantined))
	for _, r := range h.quarantined {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func (h *Hammer) isPGIDSafe(pgid int) bool {
	if pgid <= 1 {
		return false
	}
	h.mu.Lock()
	protected := make([]int, 0, len(h.protected))
	for p := range h.protected {
		protected = append(protected, p)
	}
	h.mu.Unlock()
	for _, p := range protected {
		if p <= 1 {
			continue
		}
		if p == pgid {
			return false
		}
		if g, err := syscall.Getpgid(p); err == nil && g == pgid {
			return false
		}
	}
	return true
}

func (h *Hammer) ancestorPIDs(pid int) []int {
	root := h.ProcRoot
	if root == "" {
		root = "/proc"
	}
	var out []int
	seen := map[int]bool{}
	cur := pid
	for cur > 1 && !seen[cur] {
		seen[cur] = true
		ppid := readPPID(root, cur)
		if ppid <= 1 {
			break
		}
		out = append(out, ppid)
		cur = ppid
	}
	return out
}

func readPPID(procRoot string, pid int) int {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			if err == nil {
				return v
			}
		}
	}
	return 0
}
