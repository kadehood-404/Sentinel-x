//go:build linux

package sigil

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
)

func TestSigilIPCThreatElevationOverridesAndLedgerAudit(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sigil.sock")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")

	led, err := ledger.Open(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()

	rs, err := policy.Load("../../rules/bridge")
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(policy.Enforce, rs)

	srv, err := NewServer(ServerConfig{
		SocketPath: sockPath,
		Hostname:   "test",
		Ledger:     led,
		Handlers: Handlers{
			OnThreatSignal: func(sig ThreatSignalPayload, source string, peer PeerInfo) {
				lvl, err := policy.ParseLockLevel(sig.RecommendedLock)
				if err != nil || lvl == policy.LockNormal {
					lvl = policy.LockElevated
				}
				ttl := time.Duration(sig.TTLSeconds) * time.Second
				if ttl <= 0 {
					ttl = 5 * time.Minute
				}
				eng.ElevateSession(sig.Session, lvl, ttl, sig.Note, source)
			},
			OnControlCmd: func(cmd ControlCmdPayload, peer PeerInfo) (bool, string, *StateSnapshot) {
				switch cmd.Cmd {
				case "override_rule":
					ttl := time.Duration(cmd.TTLSeconds) * time.Second
					if _, err := eng.AddOverride(cmd.RuleID, cmd.Session, ttl, cmd.Reason); err != nil {
						return false, err.Error(), nil
					}
					return true, "override added", nil
				case "status":
					s := StateSnapshot{
						Mode:      eng.Mode().String(),
						Sessions:  eng.ActiveSessionLocks(),
						Overrides: eng.ActiveOverrides(),
					}
					return true, "ok", &s
				default:
					return false, "unknown cmd", nil
				}
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()

	// Verify socket permissions are 0600.
	st, err := os.Stat(sockPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket perms = %o, err=%v; want 0600", st.Mode().Perm(), err)
	}

	// 1. Sentry sends prompt_injection signal -> elevates session lock -> blocks shell tool call.
	sentry, err := Dial(sockPath, "sigil-sentry")
	if err != nil {
		t.Fatal(err)
	}
	defer sentry.Close()

	ack, err := sentry.SendThreatSignal(ThreatSignalPayload{
		Session:         "agent-42",
		Severity:        "high",
		Category:        "prompt_injection",
		RuleID:          "injection-strong",
		Confidence:      0.95,
		RecommendedLock: "elevated",
		TTLSeconds:      300,
		Note:            "injection on /api/chat",
	})
	if err != nil || !ack.OK {
		t.Fatalf("SendThreatSignal failed: ack=%+v err=%v", ack, err)
	}

	// Verify shell call for agent-42 is now blocked!
	v := eng.Evaluate(policy.Input{
		Target: "tool_call", Session: "agent-42", Tool: "bash", ArgText: "ls", Workspace: "/work",
	})
	if !v.Blocks() {
		t.Fatalf("expected elevated session lock to block bash tool call")
	}

	// 2. Legacy sigil-proxy JSON payload is normalized cleanly into threat_signal.
	if err := sentry.SendRaw([]byte(`{"timestamp":"2026-11-21T10:30:00Z","path":"/api/generate","matched_types":["EMAIL","AWS_KEY"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := sentry.ReadNext(3 * time.Second); err != nil {
		t.Fatalf("legacy sigil-proxy ack failed: %v", err)
	}
	if lk := eng.SessionLock("sigil-proxy"); lk.Level != "elevated" {
		t.Fatalf("expected legacy sigil-proxy payload to elevate session, got %+v", lk)
	}

	// 3. control_cmd override_rule enforces positive bounded TTL and logs every control_cmd to ledger.
	tui, err := Dial(sockPath, "sentinel-tui")
	if err != nil {
		t.Fatal(err)
	}
	defer tui.Close()

	badAck1, err := tui.RequestControl(ControlCmdPayload{Cmd: "override_rule", RuleID: "tool-destructive-shell", Session: "agent-42", TTLSeconds: 0})
	if err != nil || badAck1.OK {
		t.Fatalf("expected TTL=0 override to be rejected: %+v err=%v", badAck1, err)
	}
	badAck2, err := tui.RequestControl(ControlCmdPayload{Cmd: "override_rule", RuleID: "tool-destructive-shell", Session: "agent-42", TTLSeconds: 9999})
	if err != nil || badAck2.OK {
		t.Fatalf("expected TTL=9999 override to be rejected: %+v err=%v", badAck2, err)
	}
	goodAck, err := tui.RequestControl(ControlCmdPayload{Cmd: "override_rule", RuleID: "tool-destructive-shell", Session: "agent-42", TTLSeconds: 120, Reason: "approved"})
	if err != nil || !goodAck.OK {
		t.Fatalf("expected bounded override to succeed: %+v err=%v", goodAck, err)
	}
	statusAck, err := tui.RequestControl(ControlCmdPayload{Cmd: "status"})
	if err != nil || !statusAck.OK || statusAck.State == nil || len(statusAck.State.Overrides) != 1 {
		t.Fatalf("status snapshot unexpected: %+v err=%v", statusAck, err)
	}

	// Verify all 4 control_cmds were written to the hash-chained ledger and chain verifies intact!
	n, err := ledger.Verify(ledgerPath)
	if err != nil {
		t.Fatalf("ledger verify failed: %v", err)
	}
	if n != 4 {
		t.Fatalf("expected 4 control_cmd audit records in ledger, got %d", n)
	}
	raw, _ := os.ReadFile(ledgerPath)
	if !strings.Contains(string(raw), `"resource":"control_cmd"`) || !strings.Contains(string(raw), `"ttl_seconds":120`) {
		t.Fatalf("ledger missing expected control_cmd audit fields:\n%s", raw)
	}

	// Verify DecodeFrame handles invalid version cleanly.
	badEnv, _ := json.Marshal(map[string]any{"v": 99, "type": "hello"})
	if _, err := DecodeFrame(badEnv); err == nil {
		t.Fatal("expected unsupported version error")
	}
}
