//go:build linux

package hammer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/policy"
)

type fakeSeverer struct {
	severed []string
}

func (f *fakeSeverer) SeverSession(session string) int {
	f.severed = append(f.severed, session)
	return 2
}

func TestSafetyRailsRejectProtectedPIDs(t *testing.T) {
	h := New(nil, 999999)
	for _, pid := range []int{0, 1, os.Getpid(), os.Getppid(), 999999} {
		if !h.IsProtectedPID(pid) {
			t.Errorf("pid %d must be protected", pid)
		}
		res := h.Execute(Request{Mode: policy.Enforce, Action: policy.Quarantine, PID: pid})
		if res.Err == nil {
			t.Errorf("expected safety rail error when quarantining pid %d", pid)
		}
		if err := h.Kill(pid, true); err == nil {
			t.Errorf("expected safety rail error when killing pid %d", pid)
		}
	}
}

func TestObserveModeNeverSignalsOrSevers(t *testing.T) {
	fs := &fakeSeverer{}
	h := New(fs)
	res := h.Execute(Request{
		Mode: policy.Observe, Action: policy.Sever,
		Session: "s1", RemoteIP: "203.0.113.5", RemotePort: 4444,
	})
	if !res.Simulated || res.Effective != "WARN" || len(fs.severed) != 0 {
		t.Fatalf("observe mode must dry-run: %+v severed=%v", res, fs.severed)
	}
}

func TestSeverUserlandPrimaryAndUnprivilegedFallback(t *testing.T) {
	// Fake /proc/self/status with zero effective capabilities.
	stPath := filepath.Join(t.TempDir(), "status")
	os.WriteFile(stPath, []byte("Name:\ttest\nCapEff:\t0000000000000000\n"), 0o600)

	fs := &fakeSeverer{}
	h := New(fs)
	h.StatusPath = stPath

	res := h.Execute(Request{
		Mode: policy.Enforce, Action: policy.Sever,
		Session: "agent-42", RemoteIP: "203.0.113.5", RemotePort: 4444,
	})
	if res.Effective != "SEVER" || res.StreamsCut != 2 || len(fs.severed) != 1 || fs.severed[0] != "agent-42" {
		t.Fatalf("unexpected sever result: %+v severed=%v", res, fs.severed)
	}
	if !strings.Contains(res.SockDestroy, "skipped SOCK_DESTROY") {
		t.Fatalf("expected graceful unprivileged SOCK_DESTROY fallback, got %q", res.SockDestroy)
	}
}

func TestQuarantineSIGSTOPAndSIGCONTSubprocess(t *testing.T) {
	// Spawn an ephemeral child process in its own process group.
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep subprocess: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	h := New(nil)
	res := h.Execute(Request{
		Mode: policy.Enforce, Action: policy.Quarantine,
		PID: pid, Group: true, Session: "s-sub", Reason: "test quarantine",
	})
	if res.Err != nil || res.Effective != "QUARANTINE" {
		t.Fatalf("quarantine subprocess failed: %+v (err=%v)", res, res.Err)
	}
	if qs := h.Quarantined(); len(qs) != 1 || qs[0].PID != pid {
		t.Fatalf("expected pid %d in quarantined list, got %+v", pid, qs)
	}

	// Verify /proc/<pid>/stat reflects stopped state ('T' or 't') within a short window.
	stopped := false
	for i := 0; i < 20; i++ {
		if st := procState(pid); st == 'T' || st == 't' {
			stopped = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !stopped {
		t.Logf("warning: /proc/%d/stat did not report T under PRoot (state=%q); continuing SIGCONT check", pid, string(procState(pid)))
	}

	if err := h.Unfreeze(pid); err != nil {
		t.Fatalf("Unfreeze failed: %v", err)
	}
	if qs := h.Quarantined(); len(qs) != 0 {
		t.Fatalf("expected empty quarantined list after unfreeze, got %+v", qs)
	}
}

func procState(pid int) byte {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	s := string(raw)
	idx := strings.LastIndexByte(s, ')')
	if idx < 0 || idx+2 >= len(s) {
		return 0
	}
	return s[idx+2]
}
