//go:build linux

// sentinel-x: unified single-binary layered enforcement daemon & CLI.
//
// Subcommands:
//
//	sentinel-x run       Run full stack (bridge + tap + core + hammer + sigil-sync + alerts)
//	sentinel-x bridge    Run standalone LLM perimeter proxy & /v1/check gate
//	sentinel-x tap       Run standalone host telemetry watcher (/proc, parent-dir FIM, sockets)
//	sentinel-x exec      Policy-check and execute a command in a workspace
//	sentinel-x mcp-shim  Strict-stdio MCP JSON-RPC policy proxy
//	sentinel-x tui       Attach raw-ANSI operator console to sigil.sock
//	sentinel-x status    Query live daemon state over sigil.sock
//	sentinel-x unfreeze  Resume a quarantined PID over sigil.sock
//	sentinel-x lint      Validate YAML rulebooks strictly
//	sentinel-x verify    Verify SHA-256 hash-chained audit ledger
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/alert"
	"github.com/kadehood-404/sentinel-x/internal/bridge"
	"github.com/kadehood-404/sentinel-x/internal/bus"
	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/hammer"
	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
	"github.com/kadehood-404/sentinel-x/internal/scan"
	"github.com/kadehood-404/sentinel-x/internal/sigil"
	"github.com/kadehood-404/sentinel-x/internal/tap"
	"github.com/kadehood-404/sentinel-x/internal/tui"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	var err error
	switch sub {
	case "run":
		err = cmdRun(args)
	case "bridge":
		err = cmdBridge(args)
	case "tap":
		err = cmdTap(args)
	case "exec":
		err = cmdExec(args)
	case "mcp-shim":
		err = cmdMCPShim(args)
	case "tui":
		err = cmdTUI(args)
	case "status":
		err = cmdStatus(args)
	case "unfreeze":
		err = cmdUnfreeze(args)
	case "lint":
		err = cmdLint(args)
	case "verify":
		err = cmdVerify(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "sentinel-x: unknown subcommand %q\n\n", sub)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-x:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `sentinel-x — layered enforcement for local LLM endpoints, agents, and hosts

Usage:
  sentinel-x run [flags]              Run full daemon (bridge + tap + core + hammer + sigil-sync + alerts)
  sentinel-x bridge [flags]           Run perimeter LLM proxy & /v1/check tool gate
  sentinel-x tap [flags]              Run userland host telemetry watcher (/proc, parent-dir FIM, sockets)
  sentinel-x exec [flags] -- <cmd>    Policy-check and execute a command
  sentinel-x mcp-shim [flags] -- <cmd> Strict-stdio MCP JSON-RPC policy proxy
  sentinel-x tui [-sigil-sock path]   Attach raw-ANSI operator console
  sentinel-x status [-sigil-sock p]   Print live daemon status from sigil.sock
  sentinel-x unfreeze [-sigil-sock] <pid>  Resume a quarantined PID
  sentinel-x lint <rules-dir>         Validate YAML rulebooks
  sentinel-x verify <ledger-file>     Verify SHA-256 hash-chained audit ledger`)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		listen        = fs.String("listen", "127.0.0.1:11435", "bridge listen address (loopback only unless -allow-nonlocal)")
		upstream      = fs.String("upstream", "http://127.0.0.1:11434", "upstream LLM endpoint (Ollama / OpenAI-compatible)")
		rulesDir      = fs.String("rules", "rules", "root directory of YAML rulebooks (hot-reloaded)")
		ledgerPath    = fs.String("ledger", "sentinel-ledger.jsonl", "append-only SHA-256 hash-chained audit ledger")
		modeS         = fs.String("mode", "observe", "observe (dry-run, log only) or enforce")
		workspace     = fs.String("workspace", "", "default agent workspace (default: current directory)")
		sockPath      = fs.String("sigil-sock", sigil.DefaultSocketPath(), "Unix domain socket path for sigil-sync IPC")
		fimPaths      = fs.String("fim-paths", "~/.ssh,.env,~/.aws/credentials,~/.gnupg", "comma-separated paths for parent-directory FIM")
		enableTap     = fs.Bool("tap", true, "enable userland sentinel-tap sensors (/proc, FIM, /proc/net)")
		tapInterval   = fs.Duration("tap-interval", 2*time.Second, "poll interval for /proc and /proc/net sensors")
		allowNonlocal = fs.Bool("allow-nonlocal", false, "allow non-loopback bridge listener (unauthenticated)")
		webhookURL    = fs.String("webhook-url", os.Getenv("SENTINEL_WEBHOOK_URL"), "optional alert webhook URL")
		webhookSecret = fs.String("webhook-secret", os.Getenv("SENTINEL_WEBHOOK_SECRET"), "optional HMAC-SHA256 webhook secret")
		encryptKey    = fs.String("webhook-encrypt-key", os.Getenv("SENTINEL_WEBHOOK_ENCRYPT_KEY"), "optional AES-256-GCM payload encryption key")
		tgToken       = fs.String("telegram-token", os.Getenv("SENTINEL_TELEGRAM_TOKEN"), "optional Telegram Bot API token")
		tgChatID      = fs.String("telegram-chat-id", os.Getenv("SENTINEL_TELEGRAM_CHAT_ID"), "optional Telegram chat ID")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := log.New(os.Stderr, "sentinel-x: ", log.LstdFlags)
	loop, err := bridge.IsLoopback(*listen)
	if err != nil {
		return err
	}
	if !loop && !*allowNonlocal {
		return fmt.Errorf("refusing to listen on %s without -allow-nonlocal", *listen)
	}
	mode, err := policy.ParseMode(*modeS)
	if err != nil {
		return err
	}
	up, err := url.Parse(*upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return fmt.Errorf("bad -upstream %q", *upstream)
	}
	if *workspace == "" {
		if *workspace, err = os.Getwd(); err != nil {
			return err
		}
	}

	rs, err := policy.Load(*rulesDir)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	eng := policy.NewEngine(mode, rs)

	led, err := ledger.Open(*ledgerPath)
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}
	defer led.Close()

	host, _ := os.Hostname()
	evBus := bus.New(256)
	alerter := alert.New(alert.Config{
		WebhookURL:     *webhookURL,
		WebhookSecret:  *webhookSecret,
		EncryptKey:     *encryptKey,
		TelegramToken:  *tgToken,
		TelegramChatID: *tgChatID,
		Logf:           logger.Printf,
	})

	var (
		br       *bridge.Server
		ham      *hammer.Hammer
		sigilSrv *sigil.Server
	)

	handleVerdict := func(ev event.Event, v policy.Verdict) {
		evBus.Publish(bus.Message{Topic: bus.TopicVerdict, Event: ev})
		alerter.Submit(ev)
		if sigilSrv != nil {
			if env, err := sigil.NewEnvelope("sentinel-x", sigil.TypeVerdictEvent, ev); err == nil {
				sigilSrv.Broadcast(env)
			}
		}
		if ham != nil && v.Action() >= policy.Throttle {
			remIP, _ := ev.Raw["remote_ip"].(string)
			remPort, _ := ev.Raw["remote_port"].(int)
			res := ham.Execute(hammer.Request{
				Mode:       v.Mode,
				Action:     v.Action(),
				Session:    ev.Session,
				PID:        ev.PID,
				RemoteIP:   remIP,
				RemotePort: remPort,
				RuleIDs:    v.RuleIDs(),
				Reason:     fmt.Sprintf("%s on %s", v.Action(), ev.Object.Value),
			})
			if res.Err != nil {
				logger.Printf("hammer %s failed: %v", v.Action(), res.Err)
			}
			if sigilSrv != nil && (res.Effective == "SEVER" || res.Effective == "QUARANTINE" || res.Effective == "THROTTLE") {
				if env, err := sigil.NewEnvelope("sentinel-x", sigil.TypeContainmentEvent, sigil.ContainmentEventPayload{
					EventID:   ev.EventID,
					Session:   ev.Session,
					PID:       ev.PID,
					Action:    res.Action,
					Effective: res.Effective,
					Mode:      v.Mode.String(),
					RuleIDs:   v.RuleIDs(),
					Reason:    res.Detail,
				}); err == nil {
					sigilSrv.Broadcast(env)
				}
			}
		}
	}

	br = bridge.New(bridge.Config{
		Upstream:  up,
		Engine:    eng,
		Ledger:    led,
		Workspace: *workspace,
		Hostname:  host,
		OnVerdict: handleVerdict,
		Logf:      logger.Printf,
	})
	ham = hammer.New(br)

	snapshotFn := func() sigil.StateSnapshot {
		curRS := eng.Ruleset()
		seq, hash := led.Head()
		var peers []sigil.PeerInfo
		if sigilSrv != nil {
			peers = sigilSrv.Peers()
		}
		return sigil.StateSnapshot{
			Mode:           eng.Mode().String(),
			RulesCount:     len(curRS.Rules),
			RulesVersion:   curRS.Signature,
			LedgerSeq:      seq,
			LedgerHash:     hash,
			AlertsSent:     alerter.SentCount(),
			Peers:          peers,
			Sessions:       eng.ActiveSessionLocks(),
			Overrides:      eng.ActiveOverrides(),
			Quarantined:    ham.Quarantined(),
			RecentVerdicts: evBus.Recent(64),
		}
	}

	sigilSrv, err = sigil.NewServer(sigil.ServerConfig{
		SocketPath: *sockPath,
		Hostname:   host,
		Ledger:     led,
		Logf:       logger.Printf,
		Handlers: sigil.Handlers{
			Snapshot: snapshotFn,
			OnThreatSignal: func(sig sigil.ThreatSignalPayload, source string, peer sigil.PeerInfo) {
				lvl, err := policy.ParseLockLevel(sig.RecommendedLock)
				if err != nil || lvl == policy.LockNormal {
					if sig.Severity == "high" {
						lvl = policy.LockLocked
					} else {
						lvl = policy.LockElevated
					}
				}
				ttl := time.Duration(sig.TTLSeconds) * time.Second
				if ttl <= 0 {
					ttl = 5 * time.Minute
				}
				eng.ElevateSession(sig.Session, lvl, ttl, sig.Note, source)

				// Evaluate against sigil_signal rules & record in ledger.
				kind := "injection"
				if sig.Category == "secret_leak" {
					kind = "secret"
				} else if sig.Category == "pii_leak" {
					kind = "pii"
				}
				conf := sig.Confidence
				if conf <= 0 {
					conf = 0.9
				}
				v := eng.Evaluate(policy.Input{
					Target:   "sigil_signal",
					Session:  sig.Session,
					ArgText:  sig.Note,
					Findings: []policy.Finding{{Kind: kind, Name: sig.Category, Confidence: conf}},
				})
				ev := event.New()
				ev.Source = event.Source{Type: "sigil", Sensor: source, Hostname: host}
				ev.Action = event.Action{Category: "anomaly", Verb: "scan"}
				ev.Object = event.Object{Resource: "sigil_signal", Value: sig.Category}
				ev.Detection = event.Detection{Method: "signature", Confidence: conf}
				ev.Severity = sig.Severity
				if ev.Severity == "" {
					ev.Severity = v.Severity()
				}
				ev.Session = sig.Session
				ev.Verdict = &event.Verdict{
					Mode:      v.Mode.String(),
					Action:    v.Action().String(),
					Effective: v.Effective().String(),
					Rules:     v.RuleIDs(),
				}
				ev.Raw = map[string]any{"source": source, "lock_level": lvl.String(), "note": sig.Note}
				_, _ = led.Append(ev)
				handleVerdict(ev, v)
			},
			OnControlCmd: func(cmd sigil.ControlCmdPayload, peer sigil.PeerInfo) (bool, string, *sigil.StateSnapshot) {
				switch cmd.Cmd {
				case "status":
					s := snapshotFn()
					return true, "ok", &s
				case "unfreeze":
					if err := ham.Unfreeze(cmd.PID); err != nil {
						return false, err.Error(), nil
					}
					s := snapshotFn()
					return true, fmt.Sprintf("resumed pid %d", cmd.PID), &s
				case "kill":
					if err := ham.Kill(cmd.PID, cmd.Force); err != nil {
						return false, err.Error(), nil
					}
					s := snapshotFn()
					return true, fmt.Sprintf("terminated pid %d", cmd.PID), &s
				case "set_mode":
					m, err := policy.ParseMode(cmd.Mode)
					if err != nil {
						return false, err.Error(), nil
					}
					eng.SetMode(m)
					s := snapshotFn()
					return true, "mode set to " + m.String(), &s
				case "set_session_lock":
					lvl, err := policy.ParseLockLevel(cmd.LockLevel)
					if err != nil {
						return false, err.Error(), nil
					}
					ttl := time.Duration(cmd.TTLSeconds) * time.Second
					eng.SetSessionLock(cmd.Session, lvl, ttl, cmd.Reason, peer.Source)
					if lvl == policy.LockNormal {
						br.UnrevokeSession(cmd.Session)
					}
					s := snapshotFn()
					return true, fmt.Sprintf("session %s lock=%s", cmd.Session, lvl), &s
				case "override_rule":
					ttl := time.Duration(cmd.TTLSeconds) * time.Second
					ov, err := eng.AddOverride(cmd.RuleID, cmd.Session, ttl, cmd.Reason)
					if err != nil {
						return false, err.Error(), nil
					}
					s := snapshotFn()
					return true, fmt.Sprintf("override %s active until %s", ov.RuleID, ov.ExpiresAt.Format(time.RFC3339)), &s
				case "clear_override":
					eng.ClearOverride(cmd.RuleID, cmd.Session)
					s := snapshotFn()
					return true, "override cleared", &s
				default:
					return false, "unknown control_cmd: " + cmd.Cmd, nil
				}
			},
		},
	})
	if err != nil {
		return fmt.Errorf("sigil-sync socket: %w", err)
	}
	defer sigilSrv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go policy.Watch(ctx, *rulesDir, eng, 2*time.Second, logger.Printf)
	go alerter.Run(ctx)
	go func() {
		if err := sigilSrv.Serve(ctx); err != nil {
			logger.Printf("sigil-sync stopped: %v", err)
		}
	}()

	if *enableTap {
		mgr := buildTapManager(host, *tapInterval, *fimPaths, logger.Printf)
		go mgr.Run(ctx, func(ev event.Event) {
			evaluateTapEvent(ev, eng, led, handleVerdict)
		})
	}

	hs := &http.Server{Addr: *listen, Handler: br, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shut)
	}()

	logger.Printf("mode=%s listen=%s upstream=%s sigil=%s rules=%d (v%s) tap=%v ledger=%s",
		mode, *listen, *upstream, *sockPath, len(rs.Rules), rs.Signature, *enableTap, *ledgerPath)
	if mode == policy.Observe {
		logger.Printf("observe mode: dry-run only; switch to -mode enforce (or press [m] in sentinel-x tui) to apply verdicts.")
	}
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func buildTapManager(host string, interval time.Duration, fimPathsCSV string, logf func(string, ...any)) *tap.Manager {
	var paths []string
	for _, p := range strings.Split(fimPathsCSV, ",") {
		if t := strings.TrimSpace(p); t != "" {
			paths = append(paths, t)
		}
	}
	return &tap.Manager{
		Sensors: []tap.Sensor{
			&tap.ProcSensor{Interval: interval, Hostname: host},
			&tap.NetSensor{Interval: interval, Hostname: host},
			&tap.FIMSensor{Paths: paths, PollInterval: interval, Hostname: host},
		},
		Logf: logf,
	}
}

func evaluateTapEvent(ev event.Event, eng *policy.Engine, led *ledger.Ledger, onVerdict func(event.Event, policy.Verdict)) {
	in := policy.Input{
		Target:  ev.Action.Category, // process | file | network
		Verb:    ev.Action.Verb,
		PID:     ev.PID,
		ArgText: ev.Object.Value,
	}
	switch ev.Action.Category {
	case "file":
		in.Paths = []string{ev.Object.Value}
	case "process":
		in.Process = ev.Object.Value
		in.Paths = scan.ExtractPaths(ev.Object.Value)
	case "network":
		in.Dest = ev.Object.Value
		if p, ok := ev.Raw["remote_port"].(int); ok {
			in.DestPort = p
		}
		if proc, ok := ev.Raw["process"].(string); ok {
			in.Process = proc
		}
		for _, dom := range scan.ExtractDomains(ev.Object.Value) {
			for _, f := range scan.ScanDomain(dom) {
				in.Findings = append(in.Findings, policy.Finding{Kind: string(f.Kind), Name: f.Name, Confidence: f.Confidence})
			}
		}
	}

	v := eng.Evaluate(in)
	if len(v.Matches) == 0 {
		return
	}
	ev.Severity = v.Severity()
	id := v.Matches[0].RuleID
	ev.Detection.RuleID = &id
	ev.Detection.Method = "signature"
	ev.Verdict = &event.Verdict{
		Mode:      v.Mode.String(),
		Action:    v.Action().String(),
		Effective: v.Effective().String(),
		Rules:     v.RuleIDs(),
	}
	if led != nil {
		_, _ = led.Append(ev)
	}
	if onVerdict != nil {
		onVerdict(ev, v)
	}
}

func cmdBridge(args []string) error {
	return cmdRun(append([]string{"-tap=false"}, args...))
}

func cmdTap(args []string) error {
	fs := flag.NewFlagSet("tap", flag.ContinueOnError)
	var (
		rulesDir   = fs.String("rules", "rules/tap", "tap YAML rulebook directory")
		ledgerPath = fs.String("ledger", "sentinel-ledger.jsonl", "audit ledger path")
		modeS      = fs.String("mode", "observe", "observe or enforce")
		fimPaths   = fs.String("fim-paths", "~/.ssh,.env,~/.aws/credentials,~/.gnupg", "comma-separated FIM paths")
		interval   = fs.Duration("interval", 2*time.Second, "poll interval")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	mode, err := policy.ParseMode(*modeS)
	if err != nil {
		return err
	}
	rs, err := policy.Load(*rulesDir)
	if err != nil {
		return err
	}
	eng := policy.NewEngine(mode, rs)
	led, err := ledger.Open(*ledgerPath)
	if err != nil {
		return err
	}
	defer led.Close()

	host, _ := os.Hostname()
	logger := log.New(os.Stderr, "sentinel-tap: ", log.LstdFlags)
	ham := hammer.New(nil)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Printf("mode=%s rules=%d fim=%s interval=%s", mode, len(rs.Rules), *fimPaths, *interval)
	mgr := buildTapManager(host, *interval, *fimPaths, logger.Printf)
	mgr.Run(ctx, func(ev event.Event) {
		evaluateTapEvent(ev, eng, led, func(ev event.Event, v policy.Verdict) {
			logger.Printf("%s [%s] %s (%s)", v.Effective(), strings.Join(v.RuleIDs(), ","), ev.Object.Value, ev.Source.Sensor)
			if v.Action() >= policy.Throttle {
				_ = ham.Execute(hammer.Request{Mode: v.Mode, Action: v.Action(), PID: ev.PID, RuleIDs: v.RuleIDs()})
			}
		})
	})
	return nil
}

func cmdExec(args []string) error {
	flagArgs, cmdArgs := splitDoubleDash(args)
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	var (
		rulesDir   = fs.String("rules", "rules/bridge", "YAML rulebook directory")
		ledgerPath = fs.String("ledger", "sentinel-ledger.jsonl", "audit ledger path")
		modeS      = fs.String("mode", "enforce", "observe or enforce")
		workspace  = fs.String("workspace", "", "workspace directory (default: cwd)")
		session    = fs.String("session", "cli-exec", "session identifier")
	)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(cmdArgs) == 0 {
		cmdArgs = fs.Args()
	}
	mode, err := policy.ParseMode(*modeS)
	if err != nil {
		return err
	}
	if *workspace == "" {
		if *workspace, err = os.Getwd(); err != nil {
			return err
		}
	}
	rs, err := policy.Load(*rulesDir)
	if err != nil {
		return err
	}
	led, err := ledger.Open(*ledgerPath)
	if err != nil {
		return err
	}
	defer led.Close()

	host, _ := os.Hostname()
	code, err := bridge.RunExec(context.Background(), bridge.ExecConfig{
		Engine:    policy.NewEngine(mode, rs),
		Ledger:    led,
		Workspace: *workspace,
		Session:   *session,
		Hostname:  host,
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
	}, cmdArgs)
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

func cmdMCPShim(args []string) error {
	flagArgs, childCmd := splitDoubleDash(args)
	fs := flag.NewFlagSet("mcp-shim", flag.ContinueOnError)
	fs.SetOutput(os.Stderr) // Strict stdio hygiene: never touch stdout!
	var (
		rulesDir   = fs.String("rules", "rules/bridge", "YAML rulebook directory")
		ledgerPath = fs.String("ledger", "sentinel-ledger.jsonl", "audit ledger path")
		modeS      = fs.String("mode", "enforce", "observe or enforce")
		workspace  = fs.String("workspace", "", "workspace directory (default: cwd)")
		session    = fs.String("session", "mcp-stdio", "session identifier")
	)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(childCmd) == 0 {
		childCmd = fs.Args()
	}
	mode, err := policy.ParseMode(*modeS)
	if err != nil {
		return err
	}
	if *workspace == "" {
		if *workspace, err = os.Getwd(); err != nil {
			return err
		}
	}
	rs, err := policy.Load(*rulesDir)
	if err != nil {
		return err
	}
	led, err := ledger.Open(*ledgerPath)
	if err != nil {
		return err
	}
	defer led.Close()

	host, _ := os.Hostname()
	logger := log.New(os.Stderr, "sentinel-mcp-shim: ", log.LstdFlags)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return bridge.RunMCPShim(ctx, bridge.MCPConfig{
		Engine:    policy.NewEngine(mode, rs),
		Ledger:    led,
		Workspace: *workspace,
		Session:   *session,
		Hostname:  host,
		Logf:      logger.Printf,
	}, os.Stdin, os.Stdout, os.Stderr, childCmd)
}

func cmdTUI(args []string) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	sockPath := fs.String("sigil-sock", sigil.DefaultSocketPath(), "path to sigil.sock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return tui.Run(ctx, *sockPath)
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	sockPath := fs.String("sigil-sock", sigil.DefaultSocketPath(), "path to sigil.sock")
	asJSON := fs.Bool("json", false, "output raw JSON snapshot")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cl, err := sigil.Dial(*sockPath, "sentinel-cli")
	if err != nil {
		return err
	}
	defer cl.Close()
	ack, err := cl.RequestControl(sigil.ControlCmdPayload{Cmd: "status"})
	if err != nil {
		return err
	}
	if !ack.OK || ack.State == nil {
		return fmt.Errorf("status failed: %s", ack.Message)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(ack.State)
	}
	s := ack.State
	fmt.Printf("mode=%s rules=%d (v%s) peers=%d sessions=%d overrides=%d quarantined=%d ledger=#%d alerts=%d\n",
		s.Mode, s.RulesCount, s.RulesVersion, len(s.Peers), len(s.Sessions), len(s.Overrides), len(s.Quarantined), s.LedgerSeq, s.AlertsSent)
	return nil
}

func cmdUnfreeze(args []string) error {
	fs := flag.NewFlagSet("unfreeze", flag.ContinueOnError)
	sockPath := fs.String("sigil-sock", sigil.DefaultSocketPath(), "path to sigil.sock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: sentinel-x unfreeze [-sigil-sock path] <pid>")
	}
	pid, err := strconv.Atoi(fs.Arg(0))
	if err != nil || pid <= 1 {
		return fmt.Errorf("invalid pid %q", fs.Arg(0))
	}
	cl, err := sigil.Dial(*sockPath, "sentinel-cli")
	if err != nil {
		return err
	}
	defer cl.Close()
	ack, err := cl.RequestControl(sigil.ControlCmdPayload{Cmd: "unfreeze", PID: pid, Reason: "cli unfreeze"})
	if err != nil {
		return err
	}
	if !ack.OK {
		return errors.New(ack.Message)
	}
	fmt.Println("OK:", ack.Message)
	return nil
}

func cmdLint(args []string) error {
	dir := "rules"
	if len(args) == 1 {
		dir = args[0]
	} else if len(args) > 1 {
		return errors.New("usage: sentinel-x lint [rules-dir]")
	}
	rs, err := policy.Load(dir)
	if err != nil {
		return fmt.Errorf("INVALID: %w", err)
	}
	fmt.Printf("OK: %d rules (version %s)\n", len(rs.Rules), rs.Signature)
	for _, r := range rs.Rules {
		fmt.Printf("  %-30s %-12s %-11s %-6s %s\n", r.ID, r.Target, r.Action, r.Severity, filepath.Base(r.File))
	}
	return nil
}

func cmdVerify(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sentinel-x verify <ledger-file>")
	}
	n, err := ledger.Verify(args[0])
	if err != nil {
		return fmt.Errorf("TAMPERED OR CORRUPT after %d good records: %w", n, err)
	}
	fmt.Printf("OK: %d records, SHA-256 chain intact\n", n)
	return nil
}

func splitDoubleDash(args []string) ([]string, []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}
