package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/miniyaml"
)

// Rule is one compiled policy rule. All conditions in a rule must hold.
type Rule struct {
	ID          string
	Description string
	Target      string // prompt | tool_call | response | process | file | network | sigil_signal
	Severity    string // info | low | medium | high
	Action      Action

	Tools            []string
	Verbs            []string
	ArgRegex         *regexp.Regexp
	PathRegex        *regexp.Regexp
	ProcessRegex     *regexp.Regexp
	DestRegex        *regexp.Regexp
	DestPorts        []int
	OutsideWorkspace bool
	FindingKinds     []string
	MinConfidence    float64
	MinSessionLock   LockLevel
	HasMinLock       bool
	RepeatCount      int
	RepeatWindow     time.Duration

	File string
}

// Ruleset is an immutable, loaded rulebook.
type Ruleset struct {
	Rules     []*Rule
	Signature string // changes whenever any rule file changes
	LoadedAt  time.Time
}

var (
	validTargets = map[string]bool{
		"prompt": true, "tool_call": true, "response": true,
		"process": true, "file": true, "network": true, "sigil_signal": true,
	}
	validSeverities = map[string]bool{"info": true, "low": true, "medium": true, "high": true}
	validFindings   = map[string]bool{"secret": true, "pii": true, "injection": true, "anomaly": true}
	matchKeys       = map[string]bool{
		"tool": true, "action_verb": true, "arg_regex": true, "path_regex": true,
		"process_regex": true, "dest_regex": true, "dest_port": true,
		"outside_workspace": true, "finding": true, "min_confidence": true,
		"min_session_lock": true, "repeat": true,
	}
	ruleKeys = map[string]bool{
		"id": true, "description": true, "target": true, "severity": true, "action": true, "match": true,
	}
)

// Load reads every .yaml/.yml file under dir. Any problem (bad YAML, unknown
// key, bad regex, duplicate id) is an error: a typo in a security policy must
// not silently turn into a rule that never fires.
func Load(dir string) (*Ruleset, error) {
	files, sig, err := listRuleFiles(dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .yaml/.yml rule files under %s", dir)
	}
	rs := &Ruleset{Signature: sig, LoadedAt: time.Now()}
	seen := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		doc, err := miniyaml.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		list, err := ruleList(doc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for i, item := range list {
			r, err := compileRule(item)
			if err != nil {
				return nil, fmt.Errorf("%s: rule #%d: %w", f, i+1, err)
			}
			r.File = f
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("%s: rule id %q already defined in %s", f, r.ID, prev)
			}
			seen[r.ID] = f
			rs.Rules = append(rs.Rules, r)
		}
	}
	return rs, nil
}

func listRuleFiles(dir string) ([]string, string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		if st, err := os.Stat(f); err == nil {
			fmt.Fprintf(h, "%s|%d|%d\n", f, st.Size(), st.ModTime().UnixNano())
		}
	}
	return files, hex.EncodeToString(h.Sum(nil))[:16], nil
}

func ruleList(doc any) ([]any, error) {
	switch t := doc.(type) {
	case nil:
		return nil, nil
	case []any:
		return t, nil
	case map[string]any:
		for k := range t {
			if k != "rules" {
				return nil, fmt.Errorf("unknown top-level key %q (only \"rules\" is allowed)", k)
			}
		}
		l, ok := t["rules"].([]any)
		if !ok && t["rules"] != nil {
			return nil, fmt.Errorf("\"rules\" must be a list")
		}
		return l, nil
	}
	return nil, fmt.Errorf("rulebook must be a list of rules or a map with a \"rules\" list")
}

func compileRule(item any) (*Rule, error) {
	m, ok := item.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("a rule must be a map")
	}
	for k := range m {
		if !ruleKeys[k] {
			return nil, fmt.Errorf("unknown key %q", k)
		}
	}
	r := &Rule{Severity: "medium"}
	var err error
	if r.ID, err = str(m, "id", true); err != nil {
		return nil, err
	}
	if r.Description, err = str(m, "description", false); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.ID, err)
	}
	if r.Target, err = str(m, "target", true); err != nil || !validTargets[r.Target] {
		return nil, fmt.Errorf("rule %q: target must be prompt, tool_call, response, process, file, network or sigil_signal", r.ID)
	}
	if s, _ := str(m, "severity", false); s != "" {
		if !validSeverities[s] {
			return nil, fmt.Errorf("rule %q: severity must be info, low, medium or high", r.ID)
		}
		r.Severity = s
	}
	as, err := str(m, "action", true)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.ID, err)
	}
	if r.Action, err = ParseAction(as); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.ID, err)
	}
	if r.Action == Redact && r.Target != "prompt" && r.Target != "response" {
		return nil, fmt.Errorf("rule %q: REDACT only makes sense for prompt or response rules", r.ID)
	}

	mm, ok := m["match"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rule %q: needs a \"match\" section with at least one condition", r.ID)
	}
	for k := range mm {
		if !matchKeys[k] {
			return nil, fmt.Errorf("rule %q: unknown match condition %q", r.ID, k)
		}
	}
	if r.Tools, err = strList(mm, "tool"); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.ID, err)
	}
	for i := range r.Tools {
		r.Tools[i] = strings.ToLower(r.Tools[i])
	}
	if r.Verbs, err = strList(mm, "action_verb"); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.ID, err)
	}
	for i := range r.Verbs {
		r.Verbs[i] = strings.ToLower(r.Verbs[i])
	}
	if r.FindingKinds, err = strList(mm, "finding"); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.ID, err)
	}
	for _, k := range r.FindingKinds {
		if !validFindings[k] {
			return nil, fmt.Errorf("rule %q: unknown finding kind %q", r.ID, k)
		}
	}
	if expr, _ := str(mm, "arg_regex", false); expr != "" {
		if r.ArgRegex, err = regexp.Compile(expr); err != nil {
			return nil, fmt.Errorf("rule %q: bad arg_regex: %w", r.ID, err)
		}
	}
	if expr, _ := str(mm, "path_regex", false); expr != "" {
		if r.PathRegex, err = regexp.Compile(expr); err != nil {
			return nil, fmt.Errorf("rule %q: bad path_regex: %w", r.ID, err)
		}
	}
	if expr, _ := str(mm, "process_regex", false); expr != "" {
		if r.ProcessRegex, err = regexp.Compile(expr); err != nil {
			return nil, fmt.Errorf("rule %q: bad process_regex: %w", r.ID, err)
		}
	}
	if expr, _ := str(mm, "dest_regex", false); expr != "" {
		if r.DestRegex, err = regexp.Compile(expr); err != nil {
			return nil, fmt.Errorf("rule %q: bad dest_regex: %w", r.ID, err)
		}
	}
	if r.DestPorts, err = intList(mm, "dest_port"); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.ID, err)
	}
	if v, ok := mm["outside_workspace"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			return nil, fmt.Errorf("rule %q: outside_workspace must be true or false", r.ID)
		}
		r.OutsideWorkspace = b
	}
	if v, ok := mm["min_confidence"]; ok {
		f, isNum := num(v)
		if !isNum || f < 0 || f > 1 {
			return nil, fmt.Errorf("rule %q: min_confidence must be a number from 0 to 1", r.ID)
		}
		r.MinConfidence = f
	}
	if s, err := str(mm, "min_session_lock", false); err != nil {
		return nil, fmt.Errorf("rule %q: %w", r.ID, err)
	} else if s != "" {
		lvl, err := ParseLockLevel(s)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		r.MinSessionLock = lvl
		r.HasMinLock = true
	}
	if v, ok := mm["repeat"]; ok {
		rm, isMap := v.(map[string]any)
		if !isMap {
			return nil, fmt.Errorf("rule %q: repeat needs count and window", r.ID)
		}
		for k := range rm {
			if k != "count" && k != "window" {
				return nil, fmt.Errorf("rule %q: unknown repeat key %q", r.ID, k)
			}
		}
		c, cok := num(rm["count"])
		w, wok := num(rm["window"])
		if !cok || !wok || c < 2 || w <= 0 {
			return nil, fmt.Errorf("rule %q: repeat needs count >= 2 and window > 0 (seconds)", r.ID)
		}
		r.RepeatCount = int(c)
		r.RepeatWindow = time.Duration(w * float64(time.Second))
	}
	if len(r.Tools) == 0 && len(r.Verbs) == 0 && r.ArgRegex == nil && r.PathRegex == nil &&
		r.ProcessRegex == nil && r.DestRegex == nil && len(r.DestPorts) == 0 &&
		!r.OutsideWorkspace && len(r.FindingKinds) == 0 && !r.HasMinLock && r.RepeatCount == 0 {
		return nil, fmt.Errorf("rule %q: match has no conditions", r.ID)
	}
	return r, nil
}

// matches reports whether every condition holds, with a human-readable reason.
func (r *Rule) matches(in Input, times []time.Time, now time.Time, sessionLock LockLevel) (bool, string) {
	var why []string

	if len(r.Tools) > 0 {
		hit := false
		for _, t := range r.Tools {
			if strings.EqualFold(t, in.Tool) {
				hit = true
				break
			}
		}
		if !hit {
			return false, ""
		}
		why = append(why, "tool "+in.Tool)
	}
	if len(r.Verbs) > 0 {
		hit := false
		for _, vb := range r.Verbs {
			if strings.EqualFold(vb, in.Verb) {
				hit = true
				break
			}
		}
		if !hit {
			return false, ""
		}
		why = append(why, "verb "+in.Verb)
	}
	if r.ArgRegex != nil {
		if !r.ArgRegex.MatchString(in.ArgText) {
			return false, ""
		}
		why = append(why, "arguments matched pattern")
	}
	if r.PathRegex != nil {
		matchedPath := ""
		for _, p := range in.Paths {
			if r.PathRegex.MatchString(p) {
				matchedPath = p
				break
			}
		}
		if matchedPath == "" {
			return false, ""
		}
		why = append(why, "path matched "+matchedPath)
	}
	if r.ProcessRegex != nil {
		target := in.Process
		if target == "" {
			target = in.ArgText
		}
		if !r.ProcessRegex.MatchString(target) {
			return false, ""
		}
		why = append(why, "process matched pattern")
	}
	if r.DestRegex != nil {
		if !r.DestRegex.MatchString(in.Dest) {
			return false, ""
		}
		why = append(why, "destination matched "+in.Dest)
	}
	if len(r.DestPorts) > 0 {
		hit := false
		for _, p := range r.DestPorts {
			if p == in.DestPort {
				hit = true
				break
			}
		}
		if !hit {
			return false, ""
		}
		why = append(why, fmt.Sprintf("dest_port %d", in.DestPort))
	}
	if r.OutsideWorkspace {
		p, out := OutsideWorkspace(in.Workspace, in.Paths)
		if !out {
			return false, ""
		}
		why = append(why, "path escapes workspace: "+p)
	}
	if len(r.FindingKinds) > 0 {
		var names []string
		for _, f := range in.Findings {
			for _, k := range r.FindingKinds {
				if f.Kind == k && f.Confidence >= r.MinConfidence {
					names = append(names, fmt.Sprintf("%s (%.2f)", f.Name, f.Confidence))
				}
			}
		}
		if len(names) == 0 {
			return false, ""
		}
		why = append(why, "found "+strings.Join(dedupe(names), ", "))
	}
	if r.HasMinLock {
		if sessionLock < r.MinSessionLock {
			return false, ""
		}
		why = append(why, "session lock "+sessionLock.String())
	}
	if r.RepeatCount > 0 {
		n := 0
		for _, t := range times {
			if now.Sub(t) <= r.RepeatWindow {
				n++
			}
		}
		if n < r.RepeatCount {
			return false, ""
		}
		why = append(why, fmt.Sprintf("identical input seen %d times in %s", n, r.RepeatWindow))
	}
	return true, strings.Join(why, "; ")
}

// Watch reloads dir into e whenever a rule file changes. A broken edit is
// logged and ignored: the last good ruleset keeps running.
func Watch(ctx context.Context, dir string, e *Engine, every time.Duration, logf func(string, ...any)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, sig, err := listRuleFiles(dir)
			if err != nil || sig == e.Ruleset().Signature {
				continue
			}
			rs, err := Load(dir)
			if err != nil {
				logf("rule reload failed, keeping previous rules: %v", err)
				continue
			}
			e.SetRuleset(rs)
			logf("rules reloaded: %d rules (version %s)", len(rs.Rules), rs.Signature)
		}
	}
}

func str(m map[string]any, key string, required bool) (string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		if required {
			return "", fmt.Errorf("missing %q", key)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%q must be text", key)
	}
	if required && strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("missing %q", key)
	}
	return s, nil
}

func strList(m map[string]any, key string) ([]string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%q must be a list of text values", key)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%q must be text or a list of text values", key)
}

func intList(m map[string]any, key string) ([]int, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, nil
	}
	parseOne := func(x any) (int, error) {
		switch t := x.(type) {
		case int64:
			return int(t), nil
		case float64:
			return int(t), nil
		case string:
			n, err := strconv.Atoi(t)
			if err != nil {
				return 0, fmt.Errorf("%q must be integer(s)", key)
			}
			return n, nil
		}
		return 0, fmt.Errorf("%q must be integer(s)", key)
	}
	if l, ok := v.([]any); ok {
		out := make([]int, 0, len(l))
		for _, item := range l {
			n, err := parseOne(item)
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, nil
	}
	n, err := parseOne(v)
	if err != nil {
		return nil, err
	}
	return []int{n}, nil
}

func num(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case float64:
		return t, true
	}
	return 0, false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
