package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"

	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
	"github.com/kadehood-404/sentinel-x/internal/scan"
)

// ExecConfig configures the sentinel-x exec CLI wrapper.
type ExecConfig struct {
	Engine    *policy.Engine
	Ledger    *ledger.Ledger
	Workspace string
	Session   string
	Hostname  string
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
}

// RunExec checks cmdArgs against sentinel-core before spawning the child
// process in its own process group. Returns exit code and error.
func RunExec(ctx context.Context, cfg ExecConfig, cmdArgs []string) (int, error) {
	if len(cmdArgs) == 0 {
		return 2, errors.New("exec requires a command after --")
	}
	if cfg.Session == "" {
		cfg.Session = "cli-exec"
	}
	joined := strings.Join(cmdArgs, " ")
	paths := scan.ExtractPaths(joined)
	findings := scan.Scan(joined)
	for _, dom := range scan.ExtractDomains(joined) {
		findings = append(findings, scan.ScanDomain(dom)...)
	}

	v := cfg.Engine.Evaluate(policy.Input{
		Target:    "tool_call",
		Session:   cfg.Session,
		Tool:      "shell",
		Verb:      "exec",
		ArgText:   joined,
		Paths:     paths,
		Workspace: cfg.Workspace,
		Findings:  toPolicy(findings),
	})

	if len(v.Matches) > 0 && cfg.Ledger != nil {
		ev := event.New()
		ev.Source = event.Source{Type: "agent", Sensor: "sentinel-bridge:exec", Hostname: cfg.Hostname}
		ev.Action = event.Action{Category: "process", Verb: "exec"}
		ev.Object = event.Object{Resource: "tool_call", Value: cmdArgs[0]}
		ev.Detection = event.Detection{Method: "signature", Confidence: 1}
		ev.Severity = v.Severity()
		ev.Session = cfg.Session
		ev.Verdict = &event.Verdict{
			Mode:      v.Mode.String(),
			Action:    v.Action().String(),
			Effective: v.Effective().String(),
			Rules:     v.RuleIDs(),
		}
		id := v.Matches[0].RuleID
		ev.Detection.RuleID = &id
		_, _ = cfg.Ledger.Append(ev)
	}

	if v.Blocks() {
		return 126, fmt.Errorf("blocked by sentinel-x (%s)", strings.Join(v.RuleIDs(), ", "))
	}
	if v.Applied(policy.Throttle) {
		return 126, fmt.Errorf("throttled by sentinel-x (%s)", strings.Join(v.RuleIDs(), ", "))
	}

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = cfg.Workspace
	cmd.Stdin = cfg.Stdin
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}
