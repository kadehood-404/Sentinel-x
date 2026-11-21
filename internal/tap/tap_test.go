//go:build linux

package tap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

func TestProcNetEndiannessDecoding(t *testing.T) {
	// IPv4 in /proc/net/tcp is little-endian: 0100007F -> 127.0.0.1, 057100CB -> 203.0.113.5
	ip1, err := DecodeIPv4Hex("0100007F")
	if err != nil || ip1.String() != "127.0.0.1" {
		t.Fatalf("DecodeIPv4Hex(0100007F) = %v, %v; want 127.0.0.1", ip1, err)
	}
	ip2, err := DecodeIPv4Hex("057100CB")
	if err != nil || ip2.String() != "203.0.113.5" {
		t.Fatalf("DecodeIPv4Hex(057100CB) = %v, %v; want 203.0.113.5", ip2, err)
	}

	// Port in /proc/net/tcp is big-endian: 115C -> 4444, 01BB -> 443
	p1, err := DecodePortHex("115C")
	if err != nil || p1 != 4444 {
		t.Fatalf("DecodePortHex(115C) = %d, %v; want 4444", p1, err)
	}
	p2, err := DecodePortHex("01BB")
	if err != nil || p2 != 443 {
		t.Fatalf("DecodePortHex(01BB) = %d, %v; want 443", p2, err)
	}

	// IPv6 loopback ::1 stored as four 32-bit LE words: 00000000 00000000 00000000 01000000
	ip6, err := DecodeIPv6Hex("00000000000000000000000001000000")
	if err != nil || ip6.String() != "::1" {
		t.Fatalf("DecodeIPv6Hex(::1) = %v, %v; want ::1", ip6, err)
	}

	sample := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A00000A:C350 057100CB:115C 01 00000000:00000000 00:00000000 00000000  1000        0 998877 1 0
   1: 0100007F:2CB6 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 112233 1 0
`
	entries, err := ParseProcNet(strings.NewReader(sample), "tcp", false)
	if err != nil || len(entries) != 2 {
		t.Fatalf("ParseProcNet = %d, %v", len(entries), err)
	}
	if entries[0].RemoteIP.String() != "203.0.113.5" || entries[0].RemotePort != 4444 || entries[0].Inode != 998877 {
		t.Fatalf("row 0 wrong: %+v", entries[0])
	}
	if !isOutboundSocket(entries[0], false) {
		t.Fatal("row 0 should be classified outbound")
	}
	if isOutboundSocket(entries[1], false) {
		t.Fatal("row 1 (LISTEN 0.0.0.0:0) should not be outbound")
	}
}

func TestProcAndSocketENOENTChurn(t *testing.T) {
	procRoot := t.TempDir()
	// PID 4242 has a valid socket fd symlink and a vanished fd entry.
	fdDir := filepath.Join(procRoot, "4242", "fd")
	if err := os.MkdirAll(fdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(procRoot, "4242", "comm"), []byte("curl\n"), 0o600)
	os.Symlink("socket:[998877]", filepath.Join(fdDir, "3"))
	// PID 9999 has no fd directory at all (simulating ENOENT race mid-scan).
	os.MkdirAll(filepath.Join(procRoot, "9999"), 0o700)

	m := MapSocketInodes(procRoot)
	ref, ok := m[998877]
	if !ok || ref.PID != 4242 || ref.Comm != "curl" {
		t.Fatalf("MapSocketInodes missing expected entry: %+v", m)
	}

	// Verify ProcSensor detects new PID and priv_esc while surviving ENOENT PIDs.
	writeStatus := func(pid, ppid, uid, euid int, name string) {
		dir := filepath.Join(procRoot, strconvItoa(pid))
		os.MkdirAll(dir, 0o700)
		body := "Name:\t" + name + "\nPPid:\t" + strconvItoa(ppid) + "\nUid:\t" + strconvItoa(uid) + "\t" + strconvItoa(euid) + "\n"
		os.WriteFile(filepath.Join(dir, "status"), []byte(body), 0o600)
		os.WriteFile(filepath.Join(dir, "cmdline"), []byte(name+"\x00--flag\x00"), 0o600)
	}

	ps := &ProcSensor{ProcRoot: procRoot, Hostname: "test", SelfPID: 1}
	writeStatus(100, 1, 1000, 1000, "agent")
	ps.Poll() // baseline

	// New process appears + PID 9999 still has no status file (ENOENT churn).
	writeStatus(200, 100, 1000, 1000, "sh")
	evs := ps.Poll()
	if len(evs) != 1 || evs[0].Action.Verb != "exec" || evs[0].PID != 200 {
		t.Fatalf("expected 1 exec event for pid 200, got %+v", evs)
	}

	// PID 200 escalates EUID 1000 -> 0.
	writeStatus(200, 100, 1000, 0, "sh")
	evs = ps.Poll()
	if len(evs) != 1 || evs[0].Action.Verb != "priv_esc" || evs[0].Severity != "high" {
		t.Fatalf("expected 1 priv_esc event for pid 200, got %+v", evs)
	}
}

func TestFIMParentDirAtomicRenameAndChmod(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".env")
	if err := os.WriteFile(target, []byte("SECRET=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan event.Event, 16)
	sensor := &FIMSensor{
		Paths:        []string{target},
		PollInterval: 100 * time.Millisecond,
		Hostname:     "test",
	}
	go sensor.Run(ctx, func(ev event.Event) {
		got <- ev
	})

	// Give sensor a moment to register parent-directory watch + baseline.
	time.Sleep(150 * time.Millisecond)

	// Atomic temp -> rename replacement (the classic swap that breaks inode-only watches).
	tmp := filepath.Join(dir, ".env.tmp")
	if err := os.WriteFile(tmp, []byte("SECRET=replaced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}

	// Also chmod the replaced file.
	time.Sleep(100 * time.Millisecond)
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}

	var sawRename, sawChmod bool
	deadline := time.After(2 * time.Second)
	for !(sawRename && sawChmod) {
		select {
		case ev := <-got:
			if ev.Object.Value != target {
				continue
			}
			if ev.Action.Verb == "rename" {
				sawRename = true
			}
			if ev.Action.Verb == "chmod" {
				sawChmod = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for FIM events: sawRename=%v sawChmod=%v", sawRename, sawChmod)
		}
	}
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
