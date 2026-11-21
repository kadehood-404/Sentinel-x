// Package policy is sentinel-core: a deterministic rule engine.
//
// Rulebooks are YAML files. Evaluate() takes one Input (a prompt headed for a
// model, a tool call an agent wants to run, or a telemetry event from
// sentinel-tap / sigil-sync) and returns a Verdict listing every rule that
// matched and why. Beyond a short repeat-detection window, per-session lock
// state, and time-bounded operator overrides, there is no hidden state and no
// model in the loop.
//
// Observe mode (the default) never changes what happens: enforcing actions
// are reported as "would have" and downgraded to WARN. Enforce mode applies
// them.
package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Action is ordered by severity: a higher value overrides a lower one.
type Action int

const (
	Allow Action = iota
	Warn
	Throttle
	Redact
	Block
	Sever
	Quarantine
)

var actionNames = [...]string{"ALLOW", "WARN", "THROTTLE", "REDACT", "BLOCK", "SEVER", "QUARANTINE"}

func (a Action) String() string {
	if a < 0 || int(a) >= len(actionNames) {
		return "UNKNOWN"
	}
	return actionNames[a]
}

// Enforcing reports whether the action changes behavior (anything above WARN).
func (a Action) Enforcing() bool { return a >= Throttle }

func ParseAction(s string) (Action, error) {
	for i, n := range actionNames {
		if strings.EqualFold(s, n) {
			return Action(i), nil
		}
	}
	return Allow, fmt.Errorf("unknown action %q (want one of %s)", s, strings.Join(actionNames[:], ", "))
}

type Mode int

const (
	Observe Mode = iota
	Enforce
)

func (m Mode) String() string {
	if m == Enforce {
		return "enforce"
	}
	return "observe"
}

func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "observe", "":
		return Observe, nil
	case "enforce":
		return Enforce, nil
	}
	return Observe, fmt.Errorf("unknown mode %q (want observe or enforce)", s)
}

// LockLevel controls dynamic per-session restriction posture.
type LockLevel int

const (
	LockNormal LockLevel = iota
	LockElevated
	LockLocked
)

var lockNames = [...]string{"normal", "elevated", "locked"}

func (l LockLevel) String() string {
	if l < 0 || int(l) >= len(lockNames) {
		return "normal"
	}
	return lockNames[l]
}

func ParseLockLevel(s string) (LockLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "normal":
		return LockNormal, nil
	case "elevated":
		return LockElevated, nil
	case "locked":
		return LockLocked, nil
	default:
		return LockNormal, fmt.Errorf("unknown lock level %q (want normal, elevated or locked)", s)
	}
}

// SessionLockState describes an active session restriction.
type SessionLockState struct {
	Session   string    `json:"session"`
	Level     string    `json:"level"`
	Reason    string    `json:"reason,omitempty"`
	Source    string    `json:"source,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	level LockLevel
}

// MaxOverrideTTL is the hard upper bound for any operator rule override so
// guardrails cannot be silently disabled indefinitely.
const MaxOverrideTTL = 3600 * time.Second

// RuleOverride temporarily suppresses a specific rule (globally or for one session).
type RuleOverride struct {
	RuleID    string    `json:"rule_id"`
	Session   string    `json:"session,omitempty"` // empty = global
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Finding is the policy layer's view of a scanner result.
type Finding struct {
	Kind       string
	Name       string
	Confidence float64
}

// Input is one thing to judge.
type Input struct {
	Target    string // prompt | tool_call | response | process | file | network | sigil_signal
	Session   string
	Tool      string
	Verb      string // exec | priv_esc | write | rename | chmod | delete | connect | scan
	Process   string // process name / cmdline (for tap/process/network events)
	Dest      string // remote host/ip:port or domain (for network events)
	DestPort  int    // remote port (for network events)
	PID       int    // offending PID if known
	ArgText   string // flattened text of prompt, tool arguments, cmdline, or note
	Paths     []string
	Workspace string
	Findings  []Finding
}

// Match is one rule that fired.
type Match struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
	Reason      string `json:"reason"`

	action Action
}

type Verdict struct {
	Mode    Mode
	Matches []Match
}

// Action is the strongest action any matching rule asked for.
func (v Verdict) Action() Action {
	max := Allow
	for _, m := range v.Matches {
		if m.action > max {
			max = m.action
		}
	}
	return max
}

// Effective is what actually gets applied: in observe mode nothing above WARN.
func (v Verdict) Effective() Action {
	a := v.Action()
	if v.Mode == Observe && a.Enforcing() {
		return Warn
	}
	return a
}

// Applied reports whether some matching rule asked for exactly this action
// and the engine is in enforce mode.
func (v Verdict) Applied(a Action) bool {
	if v.Mode != Enforce {
		return false
	}
	for _, m := range v.Matches {
		if m.action == a {
			return true
		}
	}
	return false
}

// Blocks reports whether the input must be stopped (BLOCK, SEVER or QUARANTINE).
func (v Verdict) Blocks() bool { return v.Mode == Enforce && v.Action() >= Block }

// Severity is the highest severity among matches, or "info".
func (v Verdict) Severity() string {
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3}
	best := "info"
	for _, m := range v.Matches {
		if rank[m.Severity] > rank[best] {
			best = m.Severity
		}
	}
	return best
}

func (v Verdict) RuleIDs() []string {
	ids := make([]string, 0, len(v.Matches))
	for _, m := range v.Matches {
		ids = append(ids, m.RuleID)
	}
	return ids
}

var elevatedBlockedTools = map[string]bool{
	"shell": true, "bash": true, "sh": true, "exec": true,
	"run_command": true, "curl": true, "wget": true, "http": true, "fetch": true,
}

// Engine evaluates inputs against the currently loaded ruleset.
type Engine struct {
	mode atomic.Int32
	rs   atomic.Pointer[Ruleset]
	now  func() time.Time

	mu        sync.Mutex
	hist      map[string][]time.Time
	locks     map[string]SessionLockState
	overrides map[string]RuleOverride // key: ruleID + "\x00" + session
}

const historyKeep = 10 * time.Minute
const historyMaxKeys = 4096

func NewEngine(mode Mode, rs *Ruleset) *Engine {
	e := &Engine{
		now:       time.Now,
		hist:      map[string][]time.Time{},
		locks:     map[string]SessionLockState{},
		overrides: map[string]RuleOverride{},
	}
	e.mode.Store(int32(mode))
	e.rs.Store(rs)
	return e
}

func (e *Engine) Mode() Mode             { return Mode(e.mode.Load()) }
func (e *Engine) SetMode(m Mode)         { e.mode.Store(int32(m)) }
func (e *Engine) Ruleset() *Ruleset      { return e.rs.Load() }
func (e *Engine) SetRuleset(rs *Ruleset) { e.rs.Store(rs) }

// SetSessionLock sets or clears a dynamic lock level for session.
// If level == LockNormal, the session lock is removed.
func (e *Engine) SetSessionLock(session string, level LockLevel, ttl time.Duration, reason, source string) SessionLockState {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if level == LockNormal {
		delete(e.locks, session)
		return SessionLockState{Session: session, Level: LockNormal.String(), UpdatedAt: now}
	}
	st := SessionLockState{
		Session:   session,
		Level:     level.String(),
		Reason:    reason,
		Source:    source,
		UpdatedAt: now,
		level:     level,
	}
	if ttl > 0 {
		st.ExpiresAt = now.Add(ttl)
	}
	e.locks[session] = st
	return st
}

// ElevateSession raises session's lock level to at least level (never lowers it)
// and extends TTL if longer than the existing expiration.
func (e *Engine) ElevateSession(session string, level LockLevel, ttl time.Duration, reason, source string) SessionLockState {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, ok := e.locks[session]
	if ok && !cur.ExpiresAt.IsZero() && now.After(cur.ExpiresAt) {
		delete(e.locks, session)
		ok = false
	}
	if !ok || level > cur.level {
		cur = SessionLockState{
			Session:   session,
			Level:     level.String(),
			Reason:    reason,
			Source:    source,
			UpdatedAt: now,
			level:     level,
		}
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		if cur.ExpiresAt.IsZero() || exp.After(cur.ExpiresAt) {
			cur.ExpiresAt = exp
		}
	}
	e.locks[session] = cur
	return cur
}

// SessionLock returns the current non-expired lock state for session.
func (e *Engine) SessionLock(session string) SessionLockState {
	if session == "" {
		return SessionLockState{Level: LockNormal.String()}
	}
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.locks[session]
	if !ok {
		return SessionLockState{Session: session, Level: LockNormal.String()}
	}
	if !st.ExpiresAt.IsZero() && now.After(st.ExpiresAt) {
		delete(e.locks, session)
		return SessionLockState{Session: session, Level: LockNormal.String()}
	}
	return st
}

// ActiveSessionLocks returns all non-expired session locks sorted by session name.
func (e *Engine) ActiveSessionLocks() []SessionLockState {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]SessionLockState, 0, len(e.locks))
	for k, st := range e.locks {
		if !st.ExpiresAt.IsZero() && now.After(st.ExpiresAt) {
			delete(e.locks, k)
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Session < out[j].Session })
	return out
}

// AddOverride registers a time-bounded override suppressing ruleID (optionally
// scoped to session). ttl must be > 0 and <= MaxOverrideTTL.
func (e *Engine) AddOverride(ruleID, session string, ttl time.Duration, reason string) (RuleOverride, error) {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return RuleOverride{}, fmt.Errorf("rule_id is required for override")
	}
	if ttl <= 0 || ttl > MaxOverrideTTL {
		return RuleOverride{}, fmt.Errorf("ttl must be > 0s and <= %s (got %s)", MaxOverrideTTL, ttl)
	}
	now := e.now()
	ov := RuleOverride{
		RuleID:    ruleID,
		Session:   strings.TrimSpace(session),
		Reason:    reason,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	e.mu.Lock()
	e.overrides[overrideKey(ov.RuleID, ov.Session)] = ov
	e.mu.Unlock()
	return ov, nil
}

// ClearOverride removes a previously registered override.
func (e *Engine) ClearOverride(ruleID, session string) bool {
	k := overrideKey(strings.TrimSpace(ruleID), strings.TrimSpace(session))
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.overrides[k]
	delete(e.overrides, k)
	return ok
}

// ActiveOverrides returns all non-expired overrides sorted by rule ID.
func (e *Engine) ActiveOverrides() []RuleOverride {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RuleOverride, 0, len(e.overrides))
	for k, ov := range e.overrides {
		if now.After(ov.ExpiresAt) {
			delete(e.overrides, k)
			continue
		}
		out = append(out, ov)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID == out[j].RuleID {
			return out[i].Session < out[j].Session
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func (e *Engine) isOverridden(ruleID, session string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, k := range []string{overrideKey(ruleID, session), overrideKey(ruleID, "")} {
		ov, ok := e.overrides[k]
		if !ok {
			continue
		}
		if now.After(ov.ExpiresAt) {
			delete(e.overrides, k)
			continue
		}
		return true
	}
	return false
}

func overrideKey(ruleID, session string) string { return ruleID + "\x00" + session }

// Evaluate judges one input.
func (e *Engine) Evaluate(in Input) Verdict {
	now := e.now()
	times := e.record(in, now)
	lockState := e.SessionLock(in.Session)
	v := Verdict{Mode: e.Mode()}

	// Built-in session-lock guardrails when a session has been tightened by
	// sigil-sync or operator control.
	if lockState.level >= LockLocked && (in.Target == "tool_call" || in.Target == "prompt") {
		if !e.isOverridden("session-lock-locked", in.Session, now) {
			reason := "session is locked"
			if lockState.Reason != "" {
				reason += ": " + lockState.Reason
			}
			v.Matches = append(v.Matches, Match{
				RuleID:      "session-lock-locked",
				Description: "Session locked due to elevated threat signal",
				Severity:    "high",
				Action:      Block.String(),
				Reason:      reason,
				action:      Block,
			})
		}
	} else if lockState.level >= LockElevated && in.Target == "tool_call" && elevatedBlockedTools[strings.ToLower(in.Tool)] {
		if !e.isOverridden("session-lock-elevated", in.Session, now) {
			reason := "session lock elevated; restricted tool " + in.Tool
			if lockState.Reason != "" {
				reason += " (" + lockState.Reason + ")"
			}
			v.Matches = append(v.Matches, Match{
				RuleID:      "session-lock-elevated",
				Description: "Shell/network tool blocked while session lock is elevated",
				Severity:    "high",
				Action:      Block.String(),
				Reason:      reason,
				action:      Block,
			})
		}
	}

	rs := e.rs.Load()
	if rs != nil {
		for _, r := range rs.Rules {
			if r.Target != in.Target {
				continue
			}
			if e.isOverridden(r.ID, in.Session, now) {
				continue
			}
			if ok, why := r.matches(in, times, now, lockState.level); ok {
				v.Matches = append(v.Matches, Match{
					RuleID: r.ID, Description: r.Description, Severity: r.Severity,
					Action: r.Action.String(), Reason: why, action: r.Action,
				})
			}
		}
	}
	return v
}

// record notes this input in the repeat window and returns the timestamps of
// identical inputs (including this one) from the same session.
func (e *Engine) record(in Input, now time.Time) []time.Time {
	key := in.Session + "\x00" + in.Target + "\x00" + in.Tool + "\x00" + in.Verb + "\x00" + in.Dest + "\x00" + in.ArgText
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.hist) > historyMaxKeys {
		for k, ts := range e.hist {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > historyKeep {
				delete(e.hist, k)
			}
		}
	}
	kept := e.hist[key][:0:0]
	for _, t := range e.hist[key] {
		if now.Sub(t) <= historyKeep {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	e.hist[key] = kept
	return append([]time.Time(nil), kept...)
}

// OutsideWorkspace returns the first path that escapes workspace.
// "~" paths are always treated as outside: the home directory is not a workspace.
func OutsideWorkspace(workspace string, paths []string) (string, bool) {
	if workspace == "" {
		return "", false
	}
	ws := filepath.Clean(workspace)
	for _, p := range paths {
		if strings.HasPrefix(p, "~") {
			return p, true
		}
		abs := p
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(ws, abs)
		}
		rel, err := filepath.Rel(ws, filepath.Clean(abs))
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return p, true
		}
	}
	return "", false
}
