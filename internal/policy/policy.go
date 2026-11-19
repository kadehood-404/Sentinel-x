// Package policy is sentinel-core: a deterministic rule engine.
//
// Rulebooks are YAML files. Evaluate() takes one Input (a prompt headed for a
// model, or a tool call an agent wants to run) and returns a Verdict listing
// every rule that matched and why. There is no hidden state beyond a short
// repeat-detection window, and no model in the loop.
//
// Observe mode (the default) never changes what happens: enforcing actions
// are reported as "would have" and downgraded to WARN. Enforce mode applies
// them.
package policy

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Action is ordered by severity: a higher value overrides a lower one.
type Action int

const (
	Allow Action = iota
	Warn
	Throttle
	Redact
	Block
	Sever
	Quarantine
)

var actionNames = [...]string{"ALLOW", "WARN", "THROTTLE", "REDACT", "BLOCK", "SEVER", "QUARANTINE"}

func (a Action) String() string {
	if a < 0 || int(a) >= len(actionNames) {
		return "UNKNOWN"
	}
	return actionNames[a]
}

// Enforcing reports whether the action changes behavior (anything above WARN).
func (a Action) Enforcing() bool { return a >= Throttle }

func ParseAction(s string) (Action, error) {
	for i, n := range actionNames {
		if strings.EqualFold(s, n) {
			return Action(i), nil
		}
	}
	return Allow, fmt.Errorf("unknown action %q (want one of %s)", s, strings.Join(actionNames[:], ", "))
}

type Mode int

const (
	Observe Mode = iota
	Enforce
)

func (m Mode) String() string {
	if m == Enforce {
		return "enforce"
	}
	return "observe"
}

func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "observe", "":
		return Observe, nil
	case "enforce":
		return Enforce, nil
	}
	return Observe, fmt.Errorf("unknown mode %q (want observe or enforce)", s)
}

// Finding is the policy layer's view of a scanner result.
type Finding struct {
	Kind       string
	Name       string
	Confidence float64
}

// Input is one thing to judge.
type Input struct {
	Target    string // prompt | tool_call | response
	Session   string
	Tool      string
	ArgText   string // flattened text of the prompt or tool arguments
	Paths     []string
	Workspace string
	Findings  []Finding
}

// Match is one rule that fired.
type Match struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
	Reason      string `json:"reason"`

	action Action
}

type Verdict struct {
	Mode    Mode
	Matches []Match
}

// Action is the strongest action any matching rule asked for.
func (v Verdict) Action() Action {
	max := Allow
	for _, m := range v.Matches {
		if m.action > max {
			max = m.action
		}
	}
	return max
}

// Effective is what actually gets applied: in observe mode nothing above WARN.
func (v Verdict) Effective() Action {
	a := v.Action()
	if v.Mode == Observe && a.Enforcing() {
		return Warn
	}
	return a
}

// Applied reports whether some matching rule asked for exactly this action
// and the engine is in enforce mode.
func (v Verdict) Applied(a Action) bool {
	if v.Mode != Enforce {
		return false
	}
	for _, m := range v.Matches {
		if m.action == a {
			return true
		}
	}
	return false
}

// Blocks reports whether the input must be stopped (BLOCK, SEVER or QUARANTINE).
func (v Verdict) Blocks() bool { return v.Mode == Enforce && v.Action() >= Block }

// Severity is the highest severity among matches, or "info".
func (v Verdict) Severity() string {
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3}
	best := "info"
	for _, m := range v.Matches {
		if rank[m.Severity] > rank[best] {
			best = m.Severity
		}
	}
	return best
}

func (v Verdict) RuleIDs() []string {
	ids := make([]string, 0, len(v.Matches))
	for _, m := range v.Matches {
		ids = append(ids, m.RuleID)
	}
	return ids
}

// Engine evaluates inputs against the currently loaded ruleset.
type Engine struct {
	mode Mode
	rs   atomic.Pointer[Ruleset]
	now  func() time.Time

	mu   sync.Mutex
	hist map[string][]time.Time
}

const historyKeep = 10 * time.Minute
const historyMaxKeys = 4096

func NewEngine(mode Mode, rs *Ruleset) *Engine {
	e := &Engine{mode: mode, now: time.Now, hist: map[string][]time.Time{}}
	e.rs.Store(rs)
	return e
}

func (e *Engine) Mode() Mode             { return e.mode }
func (e *Engine) Ruleset() *Ruleset      { return e.rs.Load() }
func (e *Engine) SetRuleset(rs *Ruleset) { e.rs.Store(rs) }

// Evaluate judges one input.
func (e *Engine) Evaluate(in Input) Verdict {
	now := e.now()
	times := e.record(in, now)
	v := Verdict{Mode: e.mode}
	for _, r := range e.rs.Load().Rules {
		if r.Target != in.Target {
			continue
		}
		if ok, why := r.matches(in, times, now); ok {
			v.Matches = append(v.Matches, Match{
				RuleID: r.ID, Description: r.Description, Severity: r.Severity,
				Action: r.Action.String(), Reason: why, action: r.Action,
			})
		}
	}
	return v
}

// record notes this input in the repeat window and returns the timestamps of
// identical inputs (including this one) from the same session.
func (e *Engine) record(in Input, now time.Time) []time.Time {
	key := in.Session + "\x00" + in.Target + "\x00" + in.Tool + "\x00" + in.ArgText
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.hist) > historyMaxKeys {
		for k, ts := range e.hist {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > historyKeep {
				delete(e.hist, k)
			}
		}
	}
	kept := e.hist[key][:0:0]
	for _, t := range e.hist[key] {
		if now.Sub(t) <= historyKeep {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	e.hist[key] = kept
	return append([]time.Time(nil), kept...)
}

// OutsideWorkspace returns the first path that escapes workspace.
// "~" paths are always treated as outside: the home directory is not a workspace.
func OutsideWorkspace(workspace string, paths []string) (string, bool) {
	if workspace == "" {
		return "", false
	}
	ws := filepath.Clean(workspace)
	for _, p := range paths {
		if strings.HasPrefix(p, "~") {
			return p, true
		}
		abs := p
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(ws, abs)
		}
		rel, err := filepath.Rel(ws, filepath.Clean(abs))
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return p, true
		}
	}
	return "", false
}
