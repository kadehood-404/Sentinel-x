//go:build linux

package tap

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

// SocketEntry represents one parsed row from /proc/net/{tcp,tcp6,udp,udp6}.
type SocketEntry struct {
	Proto      string // tcp | tcp6 | udp | udp6
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      uint8
	Inode      uint64
}

// ProcRef maps a socket inode back to its owning process.
type ProcRef struct {
	PID  int
	Comm string
}

// NetSensor polls /proc/net/{tcp,tcp6,udp,udp6} and maps socket inodes to PIDs
// via /proc/<pid>/fd to report new outbound connections without packet capture.
type NetSensor struct {
	ProcRoot        string        // defaults to "/proc"
	Interval        time.Duration // defaults to 1s
	IncludeLoopback bool
	Hostname        string

	seen map[string]bool
}

func (s *NetSensor) Name() string { return "net" }

func (s *NetSensor) procRoot() string {
	if s.ProcRoot != "" {
		return s.ProcRoot
	}
	return "/proc"
}

func (s *NetSensor) Run(ctx context.Context, emit func(event.Event)) error {
	iv := s.Interval
	if iv <= 0 {
		iv = time.Second
	}
	// Baseline existing connections so startup does not flood alerts.
	s.Poll()

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

// Poll performs one pass across /proc/net/{tcp,tcp6,udp,udp6} and returns
// canonical network connect events for newly observed outbound connections.
func (s *NetSensor) Poll() []event.Event {
	root := s.procRoot()
	firstRun := s.seen == nil
	if firstRun {
		s.seen = map[string]bool{}
	}

	tables := []struct {
		file  string
		proto string
		ipv6  bool
	}{
		{"net/tcp", "tcp", false},
		{"net/tcp6", "tcp6", true},
		{"net/udp", "udp", false},
		{"net/udp6", "udp6", true},
	}

	var all []SocketEntry
	for _, tb := range tables {
		f, err := os.Open(filepath.Join(root, tb.file))
		if err != nil {
			continue
		}
		entries, _ := ParseProcNet(f, tb.proto, tb.ipv6)
		f.Close()
		all = append(all, entries...)
	}

	inodes := MapSocketInodes(root)
	cur := make(map[string]bool, len(all))
	var events []event.Event

	for _, e := range all {
		if !isOutboundSocket(e, s.IncludeLoopback) {
			continue
		}
		key := fmt.Sprintf("%s|%s:%d|%d", e.Proto, e.RemoteIP.String(), e.RemotePort, e.Inode)
		cur[key] = true
		if firstRun || s.seen[key] {
			continue
		}
		dest := net.JoinHostPort(e.RemoteIP.String(), strconv.Itoa(e.RemotePort))
		ref := inodes[e.Inode]

		ev := event.New()
		ev.Source = event.Source{Type: "network", Sensor: "sentinel-tap:net", Hostname: s.Hostname, IP: e.LocalIP.String()}
		ev.Action = event.Action{Category: "network", Verb: "connect"}
		ev.Object = event.Object{Resource: "ip", Value: dest}
		ev.Detection = event.Detection{Method: "raw", Confidence: 1}
		ev.PID = ref.PID
		ev.Raw = map[string]any{
			"proto":       e.Proto,
			"local_ip":    e.LocalIP.String(),
			"local_port":  e.LocalPort,
			"remote_ip":   e.RemoteIP.String(),
			"remote_port": e.RemotePort,
			"inode":       e.Inode,
			"pid":         ref.PID,
			"process":     ref.Comm,
		}
		events = append(events, ev)
	}
	s.seen = cur
	return events
}

func isOutboundSocket(e SocketEntry, includeLoopback bool) bool {
	if e.RemoteIP == nil || e.RemoteIP.IsUnspecified() || e.RemotePort == 0 {
		return false
	}
	if !includeLoopback && e.RemoteIP.IsLoopback() {
		return false
	}
	// TCP LISTEN (0x0A) is never an outbound connection.
	if (e.Proto == "tcp" || e.Proto == "tcp6") && e.State == 0x0A {
		return false
	}
	return true
}

// ParseProcNet parses /proc/net/{tcp,tcp6,udp,udp6} rows.
func ParseProcNet(r io.Reader, proto string, ipv6 bool) ([]SocketEntry, error) {
	sc := bufio.NewScanner(r)
	var out []SocketEntry
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || lineNo == 1 && strings.HasPrefix(line, "sl") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		lip, lport, err := parseAddrPort(fields[1], ipv6)
		if err != nil {
			continue
		}
		rip, rport, err := parseAddrPort(fields[2], ipv6)
		if err != nil {
			continue
		}
		st, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, SocketEntry{
			Proto:      proto,
			LocalIP:    lip,
			LocalPort:  lport,
			RemoteIP:   rip,
			RemotePort: rport,
			State:      uint8(st),
			Inode:      inode,
		})
	}
	return out, sc.Err()
}

func parseAddrPort(s string, ipv6 bool) (net.IP, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("bad addr:port %q", s)
	}
	var (
		ip  net.IP
		err error
	)
	if ipv6 {
		ip, err = DecodeIPv6Hex(parts[0])
	} else {
		ip, err = DecodeIPv4Hex(parts[0])
	}
	if err != nil {
		return nil, 0, err
	}
	port, err := DecodePortHex(parts[1])
	if err != nil {
		return nil, 0, err
	}
	return ip, port, nil
}

// DecodeIPv4Hex decodes a Linux /proc/net/tcp 8-char IPv4 hex address stored
// in little-endian byte order (e.g., "0100007F" -> 127.0.0.1).
func DecodeIPv4Hex(hexStr string) (net.IP, error) {
	if len(hexStr) != 8 {
		return nil, fmt.Errorf("invalid IPv4 hex length: %q", hexStr)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return net.IPv4(b[3], b[2], b[1], b[0]), nil
}

// DecodeIPv6Hex decodes a Linux /proc/net/tcp6 32-char IPv6 hex address stored
// as four 32-bit little-endian words.
func DecodeIPv6Hex(hexStr string) (net.IP, error) {
	if len(hexStr) != 32 {
		return nil, fmt.Errorf("invalid IPv6 hex length: %q", hexStr)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, net.IPv6len)
	for w := 0; w < 4; w++ {
		base := w * 4
		ip[base+0] = b[base+3]
		ip[base+1] = b[base+2]
		ip[base+2] = b[base+1]
		ip[base+3] = b[base+0]
	}
	return ip, nil
}

// DecodePortHex decodes a Linux /proc/net/* 4-char port hex value stored in
// big-endian byte order (e.g., "115C" -> 4444).
func DecodePortHex(hexStr string) (int, error) {
	v, err := strconv.ParseUint(hexStr, 16, 16)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

// MapSocketInodes walks <procRoot>/<pid>/fd to map socket inodes to owning
// processes. ENOENT/EACCES races as short-lived processes or fds vanish are
// safely ignored.
func MapSocketInodes(procRoot string) map[uint64]ProcRef {
	out := map[uint64]ProcRef{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(procRoot, ent.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// ENOENT / EACCES: normal churn on short-lived or other-user PIDs.
			continue
		}
		var comm string
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inodeStr := target[len("socket:[") : len(target)-1]
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			if comm == "" {
				if raw, err := os.ReadFile(filepath.Join(procRoot, ent.Name(), "comm")); err == nil {
					comm = strings.TrimSpace(string(raw))
				}
			}
			out[inode] = ProcRef{PID: pid, Comm: comm}
		}
	}
	return out
}
