//go:build linux

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kadehood-404/sentinel-x/internal/bridge"
	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
)

func TestLintAllRulebooks(t *testing.T) {
	if err := cmdLint([]string{"../../rules"}); err != nil {
		t.Fatalf("lint rules failed: %v", err)
	}
}

func TestExecWrapperAndLedgerVerify(t *testing.T) {
	rs, err := policy.Load("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	lp := filepath.Join(t.TempDir(), "e2e-ledger.jsonl")
	led, err := ledger.Open(lp)
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()

	eng := policy.NewEngine(policy.Enforce, rs)
	var out, errOut bytes.Buffer

	// Safe command inside workspace succeeds.
	code, err := bridge.RunExec(context.Background(), bridge.ExecConfig{
		Engine: eng, Ledger: led, Workspace: t.TempDir(), Session: "s-exec",
		Stdout: &out, Stderr: &errOut,
	}, []string{"echo", "sentinel-ok"})
	if err != nil || code != 0 || !strings.Contains(out.String(), "sentinel-ok") {
		t.Fatalf("safe exec failed: code=%d err=%v out=%q", code, err, out.String())
	}

	// Destructive command is blocked and recorded in ledger.
	code, err = bridge.RunExec(context.Background(), bridge.ExecConfig{
		Engine: eng, Ledger: led, Workspace: t.TempDir(), Session: "s-exec",
		Stdout: &out, Stderr: &errOut,
	}, []string{"rm", "-rf", "/"})
	if err == nil || code != 126 {
		t.Fatalf("expected destructive exec blocked with code 126, got code=%d err=%v", code, err)
	}

	// Tap event evaluation writes matching tap verdict to the same ledger.
	tapEv := event.New()
	tapEv.Source = event.Source{Type: "host", Sensor: "sentinel-tap:proc"}
	tapEv.Action = event.Action{Category: "process", Verb: "priv_esc"}
	tapEv.Object = event.Object{Resource: "process", Value: "exploit"}
	tapEv.PID = 98765
	var sawTapVerdict bool
	evaluateTapEvent(tapEv, eng, led, func(ev event.Event, v policy.Verdict) {
		if v.Action() == policy.Quarantine {
			sawTapVerdict = true
		}
	})
	if !sawTapVerdict {
		t.Fatal("expected tap priv_esc event to match QUARANTINE rule")
	}

	// Verify full hash-chained ledger via cmdVerify.
	if err := cmdVerify([]string{lp}); err != nil {
		t.Fatalf("cmdVerify failed: %v", err)
	}
}
