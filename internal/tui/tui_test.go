//go:build linux

package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/hammer"
	"github.com/kadehood-404/sentinel-x/internal/policy"
	"github.com/kadehood-404/sentinel-x/internal/sigil"
)

func TestRenderIncludesCoreSections(t *testing.T) {
	ev := event.New()
	ev.Source = event.Source{Sensor: "sentinel-bridge"}
	ev.Object = event.Object{Resource: "tool_call", Value: "bash"}
	ev.Severity = "high"
	ev.Session = "agent-42"
	ev.Verdict = &event.Verdict{Mode: "enforce", Action: "BLOCK", Effective: "BLOCK", Rules: []string{"tool-destructive-shell"}}

	snap := sigil.StateSnapshot{
		Mode:         "enforce",
		RulesCount:   19,
		RulesVersion: "abcdef12",
		LedgerSeq:    7,
		LedgerHash:   "0123456789abcdef0123456789abcdef",
		AlertsSent:   2,
		Sessions: []policy.SessionLockState{
			{Session: "agent-42", Level: "elevated", Reason: "injection", ExpiresAt: time.Now().Add(2 * time.Minute)},
		},
		Overrides: []policy.RuleOverride{
			{RuleID: "injection-weak", Session: "agent-42", ExpiresAt: time.Now().Add(time.Minute)},
		},
		Quarantined: []hammer.QuarantineRecord{
			{PID: 4321, PGID: 4321, Group: true, Session: "agent-42", RuleIDs: []string{"tap-proc-privesc"}, Reason: "euid=0"},
		},
		RecentVerdicts: []event.Event{ev},
	}

	out := Render(snap, UIState{Connected: true, DefaultTTLSec: 300}, 100)
	for _, want := range []string{"SENTINEL-X", "ENFORCE", "agent-42", "PID 4321", "tool-destructive-shell", "OVERRIDE", "[r]"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered TUI output missing %q:\n%s", want, out)
		}
	}
}
