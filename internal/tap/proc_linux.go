//go:build linux

package tap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

// ProcInfo holds userland process metadata scraped from /proc/<pid>.
type ProcInfo struct {
	PID     int
	PPID    int
	UID     int
	EUID    int
	Comm    string
	Cmdline string
	Exe     string
}

// ProcSensor polls /proc for new processes and effective-UID privilege
// escalations. Disappearing or unreadable PIDs (ENOENT/EACCES) are treated as
// normal churn rather than errors.
type ProcSensor struct {
	ProcRoot string        // defaults to "/proc"
	Interval time.Duration // defaults to 1s
	Hostname string
	SelfPID  int // defaults to os.Getpid()

	seen map[int]ProcInfo
}

func (s *ProcSensor) Name() string { return "proc" }

func (s *ProcSensor) procRoot() string {
	if s.ProcRoot != "" {
		return s.ProcRoot
	}
	return "/proc"
}

func (s *ProcSensor) Run(ctx context.Context, emit func(event.Event)) error {
	iv := s.Interval
	if iv <= 0 {
		iv = time.Second
	}
	// Baseline existing processes without emitting startup noise.
	s.seen = s.snapshot()

	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			for _, ev := range s.Poll() {
				emit(ev)
			}
		}
	}
}

// Poll performs one differential /proc scan and returns events for newly
// spawned processes or privilege escalations.
func (s *ProcSensor) Poll() []event.Event {
	cur := s.snapshot()
	if s.seen == nil {
		s.seen = cur
		return nil
	}
	self := s.SelfPID
	if self == 0 {
		self = os.Getpid()
	}
	var events []event.Event
	for pid, info := range cur {
		if pid == self {
			continue
		}
		prev, existed := s.seen[pid]
		if !existed {
			ev := event.New()
			ev.Source = event.Source{Type: "host", Sensor: "sentinel-tap:proc", Hostname: s.Hostname}
			ev.Action = event.Action{Category: "process", Verb: "exec"}
			val := info.Cmdline
			if val == "" {
				val = info.Comm
			}
			ev.Object = event.Object{Resource: "process", Value: val}
			ev.Detection = event.Detection{Method: "raw", Confidence: 1}
			ev.PID = pid
			ev.Raw = map[string]any{
				"pid":     pid,
				"ppid":    info.PPID,
				"uid":     info.UID,
				"euid":    info.EUID,
				"comm":    info.Comm,
				"cmdline": info.Cmdline,
				"exe":     info.Exe,
			}
			events = append(events, ev)
			continue
		}
		// Privilege escalation: existing process transitioned to EUID 0.
		if prev.EUID > 0 && info.EUID == 0 {
			ev := event.New()
			ev.Source = event.Source{Type: "host", Sensor: "sentinel-tap:proc", Hostname: s.Hostname}
			ev.Action = event.Action{Category: "process", Verb: "priv_esc"}
			ev.Object = event.Object{Resource: "process", Value: info.Comm}
			ev.Detection = event.Detection{Method: "heuristic", Confidence: 0.95}
			ev.Severity = "high"
			ev.PID = pid
			ev.Raw = map[string]any{
				"pid":       pid,
				"ppid":      info.PPID,
				"prev_euid": prev.EUID,
				"new_euid":  info.EUID,
				"comm":      info.Comm,
				"cmdline":   info.Cmdline,
				"exe":       info.Exe,
			}
			events = append(events, ev)
		}
	}
	s.seen = cur
	return events
}

func (s *ProcSensor) snapshot() map[int]ProcInfo {
	root := s.procRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return map[int]ProcInfo{}
	}
	out := make(map[int]ProcInfo, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		info, ok := ReadProcInfo(root, pid)
		if !ok {
			// Disappeared or unreadable mid-scan (ENOENT/EACCES): normal churn.
			continue
		}
		out[pid] = info
	}
	return out
}

// ReadProcInfo reads basic metadata for pid under procRoot. Returns ok=false
// when the process vanished or is inaccessible (ENOENT/EACCES).
func ReadProcInfo(procRoot string, pid int) (ProcInfo, bool) {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	statusRaw, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		if isChurnErr(err) {
			return ProcInfo{}, false
		}
		return ProcInfo{}, false
	}

	info := ProcInfo{PID: pid}
	sc := bufio.NewScanner(bytes.NewReader(statusRaw))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			info.Comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "PPid:"):
			if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))); err == nil {
				info.PPID = v
			}
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) >= 2 {
				info.UID, _ = strconv.Atoi(fields[0])
				info.EUID, _ = strconv.Atoi(fields[1])
			}
		}
	}

	if raw, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && len(raw) > 0 {
		parts := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
		ss := make([]string, 0, len(parts))
		for _, p := range parts {
			if len(p) > 0 {
				ss = append(ss, string(p))
			}
		}
		info.Cmdline = strings.Join(ss, " ")
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		info.Exe = exe
	}
	return info, true
}

func isChurnErr(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission)
}
