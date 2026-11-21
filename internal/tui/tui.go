//go:build linux

// Package tui implements sentinel-tui: a zero-dependency, raw-ANSI operator
// console ("htop meets firewall state table") connected to the Sentinel-X
// daemon over sigil.sock.
package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/sigil"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiCyan    = "\x1b[36m"
	ansiBgRed   = "\x1b[41;97m"
	ansiBgGreen = "\x1b[42;30m"
	ansiClear   = "\x1b[2J\x1b[H"
	ansiHideCur = "\x1b[?25l"
	ansiShowCur = "\x1b[?25h"
)

// UIState tracks interactive cursor/filter state for the TUI renderer.
type UIState struct {
	SelectedPIDIdx int
	FilterSeverity string // "" | "high" | "medium"
	StatusLine     string
	Connected      bool
	DefaultTTLSec  int // bounded TTL for one-key [o] rule override (default 300s)
}

// Render formats a crisp ANSI terminal frame from snap and ui without requiring
// any external TUI library.
func Render(snap sigil.StateSnapshot, ui UIState, width int) string {
	if width < 60 {
		width = 96
	}
	var b strings.Builder
	b.WriteString(ansiClear)

	// Header bar.
	modeBadge := ansiBgGreen + " OBSERVE " + ansiReset
	if strings.EqualFold(snap.Mode, "enforce") {
		modeBadge = ansiBgRed + " ENFORCE " + ansiReset
	}
	link := ansiGreen + "UP" + ansiReset
	if !ui.Connected {
		link = ansiRed + "DOWN" + ansiReset
	}
	shortHash := snap.LedgerHash
	if len(shortHash) > 10 {
		shortHash = shortHash[:10]
	}
	fmt.Fprintf(&b, "%sSENTINEL-X%s  %s  rules:%d(%s)  sigil:%s(peers:%d)  ledger:#%d(%s)  alerts:%d\r\n",
		ansiBold+ansiCyan, ansiReset, modeBadge,
		snap.RulesCount, snap.RulesVersion, link, len(snap.Peers),
		snap.LedgerSeq, shortHash, snap.AlertsSent)
	b.WriteString(ansiDim + strings.Repeat("─", width) + ansiReset + "\r\n")

	// Active Sessions & Timed Overrides.
	fmt.Fprintf(&b, "%sACTIVE SESSION LOCKS (%d)%s    %sTIMED OVERRIDES (%d)%s\r\n",
		ansiBold, len(snap.Sessions), ansiReset, ansiBold, len(snap.Overrides), ansiReset)
	if len(snap.Sessions) == 0 && len(snap.Overrides) == 0 {
		b.WriteString(ansiDim + "  (none — all sessions normal, no active rule overrides)" + ansiReset + "\r\n")
	} else {
		for _, s := range snap.Sessions {
			col := ansiYellow
			if s.Level == "locked" {
				col = ansiRed
			}
			rem := ""
			if !s.ExpiresAt.IsZero() {
				rem = fmt.Sprintf(" ttl=%s", time.Until(s.ExpiresAt).Truncate(time.Second))
			}
			fmt.Fprintf(&b, "  session=%-16s %s%-8s%s%s  %s\r\n", s.Session, col, strings.ToUpper(s.Level), ansiReset, rem, s.Reason)
		}
		for _, o := range snap.Overrides {
			rem := time.Until(o.ExpiresAt).Truncate(time.Second)
			scope := o.Session
			if scope == "" {
				scope = "*"
			}
			fmt.Fprintf(&b, "  %sOVERRIDE%s rule=%-24s session=%-12s ttl=%s\r\n", ansiYellow, ansiReset, o.RuleID, scope, rem)
		}
	}
	b.WriteString(ansiDim + strings.Repeat("─", width) + ansiReset + "\r\n")

	// Quarantined PIDs table.
	fmt.Fprintf(&b, "%sQUARANTINED PIDS (%d)%s\r\n", ansiBold, len(snap.Quarantined), ansiReset)
	if len(snap.Quarantined) == 0 {
		b.WriteString(ansiDim + "  (no quarantined processes)" + ansiReset + "\r\n")
	} else {
		for i, q := range snap.Quarantined {
			marker := "  "
			if i == ui.SelectedPIDIdx {
				marker = ansiCyan + "> " + ansiReset
			}
			grp := ""
			if q.Group {
				grp = fmt.Sprintf(" pgid=-%d", q.PGID)
			}
			fmt.Fprintf(&b, "%sPID %-7d%s  session=%-12s  rules=%s  reason=%s\r\n",
				marker, q.PID, grp, q.Session, strings.Join(q.RuleIDs, ","), q.Reason)
		}
	}
	b.WriteString(ansiDim + strings.Repeat("─", width) + ansiReset + "\r\n")

	// Live Verdicts stream.
	filterTag := "all"
	if ui.FilterSeverity != "" {
		filterTag = ui.FilterSeverity + "+"
	}
	fmt.Fprintf(&b, "%sLIVE VERDICTS & TELEMETRY%s  %s[filter: %s]%s\r\n", ansiBold, ansiReset, ansiDim, filterTag, ansiReset)
	shown := 0
	for i := len(snap.RecentVerdicts) - 1; i >= 0 && shown < 12; i-- {
		ev := snap.RecentVerdicts[i]
		if !passesSeverityFilter(ev.Severity, ui.FilterSeverity) {
			continue
		}
		shown++
		eff := "RAW"
		rules := "-"
		if ev.Verdict != nil {
			eff = ev.Verdict.Effective
			if len(ev.Verdict.Rules) > 0 {
				rules = strings.Join(ev.Verdict.Rules, ",")
			}
		}
		col := actionColor(eff, ev.Severity)
		ts := ev.Timestamp.Format("15:04:05")
		fmt.Fprintf(&b, "  %s %s%-10s%s %-18s %-24s %s:%s\r\n",
			ts, col, eff, ansiReset, ev.Source.Sensor, truncate(rules, 24), ev.Object.Resource, truncate(ev.Object.Value, 30))
	}
	if shown == 0 {
		b.WriteString(ansiDim + "  (waiting for events...)" + ansiReset + "\r\n")
	}

	b.WriteString(ansiDim + strings.Repeat("─", width) + ansiReset + "\r\n")
	if ui.StatusLine != "" {
		fmt.Fprintf(&b, "%s%s%s\r\n", ansiYellow, ui.StatusLine, ansiReset)
	}
	ttl := ui.DefaultTTLSec
	if ttl <= 0 {
		ttl = 300
	}
	fmt.Fprintf(&b, "%s[j/k]%s select  %s[r]%s resume PID  %s[x]%s kill PID  %s[o]%s override latest (%ds)  %s[m]%s mode  %s[f]%s filter  %s[q]%s quit\r\n",
		ansiBold, ansiReset, ansiBold, ansiReset, ansiBold, ansiReset,
		ansiBold, ansiReset, ttl, ansiBold, ansiReset, ansiBold, ansiReset, ansiBold, ansiReset)
	return b.String()
}

// Run attaches the interactive raw-ANSI console to sockPath until quit or ctx cancel.
func Run(ctx context.Context, sockPath string) error {
	cl, err := sigil.Dial(sockPath, "sentinel-tui")
	if err != nil {
		return fmt.Errorf("connect to %s: %w (is `sentinel-x run` active?)", sockPath, err)
	}
	defer cl.Close()

	if err := cl.Hello([]string{sigil.TypeVerdictEvent, sigil.TypeContainmentEvent, sigil.TypeThreatSignal}, true); err != nil {
		return err
	}

	restore, err := enableRawTerminal(os.Stdin.Fd())
	if err == nil {
		defer restore()
	}
	_, _ = io.WriteString(os.Stdout, ansiHideCur)
	defer func() { _, _ = io.WriteString(os.Stdout, ansiShowCur+ansiReset) }()

	ui := UIState{Connected: true, DefaultTTLSec: 300}
	var snap sigil.StateSnapshot

	evCh := make(chan sigil.Envelope, 64)
	go func() {
		_ = cl.Stream(ctx, evCh)
		close(evCh)
	}()

	keyCh := make(chan byte, 16)
	go func() {
		var buf [1]byte
		for {
			n, err := os.Stdin.Read(buf[:])
			if err != nil || n == 0 {
				return
			}
			select {
			case keyCh <- buf[0]:
			case <-ctx.Done():
				return
			}
		}
	}()

	refresh := time.NewTicker(2 * time.Second)
	defer refresh.Stop()

	draw := func() {
		if ui.SelectedPIDIdx >= len(snap.Quarantined) && len(snap.Quarantined) > 0 {
			ui.SelectedPIDIdx = len(snap.Quarantined) - 1
		}
		_, _ = io.WriteString(os.Stdout, Render(snap, ui, 96))
	}

	sendCmd := func(cmd sigil.ControlCmdPayload) {
		env, err := sigil.NewEnvelope("sentinel-tui", sigil.TypeControlCmd, cmd)
		if err != nil {
			ui.StatusLine = "error: " + err.Error()
			return
		}
		if err := cl.Send(env); err != nil {
			ui.Connected = false
			ui.StatusLine = "send failed: " + err.Error()
		}
	}

	draw()
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-refresh.C:
			sendCmd(sigil.ControlCmdPayload{Cmd: "status"})

		case env, ok := <-evCh:
			if !ok {
				ui.Connected = false
				ui.StatusLine = "disconnected from sigil.sock"
				draw()
				return nil
			}
			switch env.Type {
			case sigil.TypeStateSnapshot:
				var s sigil.StateSnapshot
				if json.Unmarshal(env.Payload, &s) == nil {
					snap = s
				}
			case sigil.TypeControlAck:
				var ack sigil.ControlAckPayload
				if json.Unmarshal(env.Payload, &ack) == nil {
					if ack.State != nil {
						snap = *ack.State
					}
					if ack.Message != "" && ack.Message != "ok" {
						ui.StatusLine = ack.Message
					}
				}
			case sigil.TypeVerdictEvent:
				var ev event.Event
				if json.Unmarshal(env.Payload, &ev) == nil {
					snap.RecentVerdicts = append(snap.RecentVerdicts, ev)
					if len(snap.RecentVerdicts) > 64 {
						snap.RecentVerdicts = snap.RecentVerdicts[len(snap.RecentVerdicts)-64:]
					}
				}
			case sigil.TypeContainmentEvent:
				sendCmd(sigil.ControlCmdPayload{Cmd: "status"})
			}
			draw()

		case k := <-keyCh:
			switch k {
			case 'q', 3: // 'q' or Ctrl-C
				return nil
			case 'j':
				if ui.SelectedPIDIdx+1 < len(snap.Quarantined) {
					ui.SelectedPIDIdx++
				}
			case 'k':
				if ui.SelectedPIDIdx > 0 {
					ui.SelectedPIDIdx--
				}
			case 'r':
				if len(snap.Quarantined) > 0 {
					pid := snap.Quarantined[ui.SelectedPIDIdx].PID
					sendCmd(sigil.ControlCmdPayload{Cmd: "unfreeze", PID: pid, Reason: "tui operator resume"})
				} else {
					ui.StatusLine = "no quarantined PID selected"
				}
			case 'x':
				if len(snap.Quarantined) > 0 {
					pid := snap.Quarantined[ui.SelectedPIDIdx].PID
					sendCmd(sigil.ControlCmdPayload{Cmd: "kill", PID: pid, Reason: "tui operator kill"})
				} else {
					ui.StatusLine = "no quarantined PID selected"
				}
			case 'm':
				next := "enforce"
				if strings.EqualFold(snap.Mode, "enforce") {
					next = "observe"
				}
				sendCmd(sigil.ControlCmdPayload{Cmd: "set_mode", Mode: next, Reason: "tui mode toggle"})
			case 'o':
				// Bounded TTL override on the most recent matched rule.
				ruleID, sess := latestRule(snap.RecentVerdicts)
				if ruleID == "" {
					ui.StatusLine = "no recent matched rule to override"
				} else {
					sendCmd(sigil.ControlCmdPayload{
						Cmd: "override_rule", RuleID: ruleID, Session: sess,
						TTLSeconds: ui.DefaultTTLSec, Reason: "tui one-key override",
					})
				}
			case 'f':
				switch ui.FilterSeverity {
				case "":
					ui.FilterSeverity = "medium"
				case "medium":
					ui.FilterSeverity = "high"
				default:
					ui.FilterSeverity = ""
				}
			}
			draw()
		}
	}
}

func latestRule(evs []event.Event) (string, string) {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Verdict != nil && len(evs[i].Verdict.Rules) > 0 {
			return evs[i].Verdict.Rules[0], evs[i].Session
		}
	}
	return "", ""
}

func passesSeverityFilter(sev, filter string) bool {
	if filter == "" {
		return true
	}
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3}
	return rank[sev] >= rank[filter]
}

func actionColor(eff, sev string) string {
	switch eff {
	case "QUARANTINE", "SEVER", "BLOCK":
		return ansiRed + ansiBold
	case "THROTTLE", "REDACT":
		return ansiYellow
	case "WARN":
		if sev == "high" {
			return ansiRed
		}
		return ansiYellow
	default:
		return ansiGreen
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

// enableRawTerminal switches fd into non-canonical raw mode using Linux
// TCGETS/TCSETS ioctls (stdlib only) and returns a restore function.
func enableRawTerminal(fd uintptr) (func(), error) {
	var orig syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&orig))); errno != 0 {
		return nil, errno
	}
	raw := orig
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Iflag &^= syscall.IXON | syscall.ICRNL
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&raw))); errno != 0 {
		return nil, errno
	}
	return func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&orig)))
	}, nil
}
