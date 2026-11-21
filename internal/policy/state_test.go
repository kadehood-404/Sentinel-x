package policy

import (
	"testing"
	"time"
)

func TestSessionLocksAndBoundedOverrides(t *testing.T) {
	e := NewEngine(Enforce, defaultRules(t))
	now := time.Unix(2_000_000, 0)
	e.now = func() time.Time { return now }

	// Safe bash call allowed initially.
	safeBash := tool("/work/agent", "bash", "ls -la")
	safeBash.Session = "agent-1"
	if v := e.Evaluate(safeBash); v.Blocks() {
		t.Fatalf("expected safe bash to be allowed initially, got %s", ids(v))
	}

	// Elevating session blocks shell tools automatically.
	e.ElevateSession("agent-1", LockElevated, 2*time.Minute, "injection detected", "sigil-sentry")
	if v := e.Evaluate(safeBash); !v.Blocks() {
		t.Fatalf("elevated session should block shell tool")
	}

	// Non-shell tool still allowed under elevated lock.
	safeRead := tool("/work/agent", "read_file", "src/a.go", "src/a.go")
	safeRead.Session = "agent-1"
	if v := e.Evaluate(safeRead); v.Blocks() {
		t.Fatalf("elevated session should allow non-shell safe read, got %s", ids(v))
	}

	// Locked session blocks everything.
	e.ElevateSession("agent-1", LockLocked, 2*time.Minute, "hard tripwire", "sigil-sentry")
	if v := e.Evaluate(safeRead); !v.Blocks() {
		t.Fatalf("locked session should block all tool calls")
	}

	// Lock expires automatically.
	now = now.Add(3 * time.Minute)
	if st := e.SessionLock("agent-1"); st.Level != "normal" {
		t.Fatalf("expected expired lock to return normal, got %s", st.Level)
	}
	if v := e.Evaluate(safeBash); v.Blocks() {
		t.Fatalf("expired lock should allow safe bash again")
	}

	// Override TTL validation: must be > 0 and <= MaxOverrideTTL.
	if _, err := e.AddOverride("tool-destructive-shell", "agent-1", 0, "bad"); err == nil {
		t.Fatal("expected error for zero override TTL")
	}
	if _, err := e.AddOverride("tool-destructive-shell", "agent-1", -time.Second, "bad"); err == nil {
		t.Fatal("expected error for negative override TTL")
	}
	if _, err := e.AddOverride("tool-destructive-shell", "agent-1", MaxOverrideTTL+time.Second, "too long"); err == nil {
		t.Fatal("expected error for override TTL above MaxOverrideTTL")
	}

	// Valid bounded override suppresses the specific rule and expires automatically.
	badCmd := tool("/work/agent", "bash", "rm -rf /")
	badCmd.Session = "agent-1"
	if _, err := e.AddOverride("tool-destructive-shell", "agent-1", 60*time.Second, "operator approved"); err != nil {
		t.Fatalf("valid override failed: %v", err)
	}
	if v := e.Evaluate(badCmd); v.Blocks() {
		t.Fatalf("overridden rule should not block during TTL, got %s", ids(v))
	}
	// Other sessions are unaffected.
	other := badCmd
	other.Session = "agent-2"
	if v := e.Evaluate(other); !v.Blocks() {
		t.Fatalf("override scoped to agent-1 must not suppress agent-2")
	}
	// Expiry restores rule automatically.
	now = now.Add(61 * time.Second)
	if v := e.Evaluate(badCmd); !v.Blocks() {
		t.Fatalf("expired override must re-enable rule automatically")
	}
}

func TestTapTargetRules(t *testing.T) {
	body := `rules:
  - id: fim-ssh
    target: file
    severity: high
    action: QUARANTINE
    match:
      action_verb: [write, rename, chmod]
      path_regex: '\.ssh/'
  - id: net-c2-port
    target: network
    severity: high
    action: SEVER
    match:
      dest_port: [4444, 1337]
  - id: proc-privesc
    target: process
    severity: high
    action: QUARANTINE
    match:
      action_verb: priv_esc
`
	rs, err := Load(writeRules(t, body))
	if err != nil {
		t.Fatalf("Load tap rules failed: %v", err)
	}
	e := NewEngine(Enforce, rs)

	v1 := e.Evaluate(Input{Target: "file", Verb: "rename", Paths: []string{"/home/octo/.ssh/authorized_keys"}})
	if v1.Action() != Quarantine {
		t.Fatalf("expected QUARANTINE on ssh rename, got %s", v1.Action())
	}
	v2 := e.Evaluate(Input{Target: "network", Verb: "connect", Dest: "203.0.113.5:4444", DestPort: 4444})
	if v2.Action() != Sever {
		t.Fatalf("expected SEVER on port 4444, got %s", v2.Action())
	}
	v3 := e.Evaluate(Input{Target: "process", Verb: "priv_esc", Process: "suspicious-bin"})
	if v3.Action() != Quarantine {
		t.Fatalf("expected QUARANTINE on priv_esc, got %s", v3.Action())
	}
}
