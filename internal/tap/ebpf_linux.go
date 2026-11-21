//go:build linux

package tap

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

// ErrBPFUnavailable is returned when the host lacks CAP_BPF/CAP_SYS_ADMIN
// (such as PRoot or unprivileged containers) so callers fall back cleanly to
// the userland Linux sensor suite.
var ErrBPFUnavailable = errors.New("eBPF sensor unavailable: requires CAP_BPF or CAP_SYS_ADMIN on native Linux")

const (
	capSysAdminBit = 21
	capBPFBit      = 39
)

// HasBPFCapability inspects CapEff in statusPath (default "/proc/self/status")
// to determine whether this process holds CAP_BPF or CAP_SYS_ADMIN.
func HasBPFCapability(statusPath string) bool {
	if statusPath == "" {
		statusPath = "/proc/self/status"
	}
	f, err := os.Open(statusPath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hexVal := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		mask, err := strconv.ParseUint(hexVal, 16, 64)
		if err != nil {
			return false
		}
		return (mask&(1<<capBPFBit)) != 0 || (mask&(1<<capSysAdminBit)) != 0
	}
	return false
}

// EBPFSensor is the capability-gated hook for optional privileged kernel
// tracing (execve, connect, openat). On unprivileged/PRoot environments it
// returns ErrBPFUnavailable immediately.
type EBPFSensor struct {
	StatusPath string
}

func (s *EBPFSensor) Name() string { return "ebpf" }

func (s *EBPFSensor) Run(ctx context.Context, emit func(event.Event)) error {
	if !HasBPFCapability(s.StatusPath) {
		return ErrBPFUnavailable
	}
	return errors.New("eBPF CO-RE ringbuf program not loaded in stdlib-only build; using userland sensors")
}
