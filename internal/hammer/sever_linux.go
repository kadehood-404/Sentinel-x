//go:build linux

package hammer

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const capNetAdminBit = 12

// HasNetAdmin checks CapEff in statusPath (default "/proc/self/status") for
// CAP_NET_ADMIN before attempting privileged netlink socket destruction.
func HasNetAdmin(statusPath string) bool {
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
		return (mask & (1 << capNetAdminBit)) != 0
	}
	return false
}

// trySockDestroy attempts a capability-gated netlink SOCK_DESTROY probe.
// In PRoot or unprivileged userland, it immediately returns a clean no-op
// fallback after stream/session severing.
func trySockDestroy(statusPath, remoteIP string, remotePort int) (bool, string) {
	if !HasNetAdmin(statusPath) {
		return false, "skipped SOCK_DESTROY (unprivileged: CAP_NET_ADMIN not present)"
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
			return false, "skipped SOCK_DESTROY (kernel/PRoot rejected NETLINK_INET_DIAG: " + err.Error() + ")"
		}
		return false, "SOCK_DESTROY socket open failed: " + err.Error()
	}
	_ = syscall.Close(fd)
	return false, "SOCK_DESTROY interface available; session stream severed"
}
