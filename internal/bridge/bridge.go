// Package bridge is sentinel-bridge: the inline gatekeeper.
//
// It does two jobs on one local port:
//
//  1. Reverse-proxies an Ollama / OpenAI-style endpoint, scanning prompts on
//     the way in. In enforce mode it redacts secrets and PII, blocks strong
//     prompt injection, and throttles runaway loops. In observe mode it
//     forwards everything untouched and only writes to the ledger.
//
//  2. Serves POST /v1/check, which an agent runner calls before executing a
//     tool ("may I run rm -rf here?") and gets back allow / warn / throttle /
//     deny.
//
// Prompt text and secret values are never written to the ledger.
package bridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
	"github.com/kadehood-404/sentinel-x/internal/scan"
)

type Config struct {
	Upstream  *url.URL
	Engine    *policy.Engine
	Ledger    *ledger.Ledger
	Workspace string // default workspace for /v1/check
	Hostname  string
	MaxBody   int64 // bytes; 0 means 4 MiB
	Logf      func(string, ...any)
}

type Server struct {
	cfg   Config
	proxy *httputil.ReverseProxy
	mux   *http.ServeMux
}

// Paths whose JSON bodies carry prompts.
var inspected = map[string]bool{
	"/api/generate":        true,
	"/api/chat":            true,
	"/v1/chat/completions": true,
	"/v1/completions":      true,
	"/v1/messages":         true,
}

// JSON keys whose string values are prompt text.
var textKeys = map[string]bool{"prompt": true, "content": true, "system": true, "input": true, "text": true}

func New(cfg Config) *Server {
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 4 << 20
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Server{cfg: cfg, proxy: httputil.NewSingleHostReverseProxy(cfg.Upstream), mux: http.NewServeMux()}
	s.proxy.FlushInterval = -1 // stream model output as it arrives
	s.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		cfg.Logf("upstream error: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream unreachable"})
	}
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		rs := cfg.Engine.Ruleset()
		writeJSON(w, 200, map[string]any{
			"ok": true, "mode": cfg.Engine.Mode().String(),
			"rules": len(rs.Rules), "rules_version": rs.Signature,
		})
	})
	s.mux.HandleFunc("/v1/check", s.handleCheck)
	s.mux.HandleFunc("/", s.handleProxy)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// ---- prompt gate -----------------------------------------------------------

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !inspected[r.URL.Path] {
		s.proxy.ServeHTTP(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBody))
	r.Body.Close()
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large for sentinel-x"})
		return
	}

	out, stop := s.inspect(w, r, body)
	if stop {
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.ContentLength = int64(len(out))
	r.Header.Set("Content-Length", strconv.Itoa(len(out)))
	s.proxy.ServeHTTP(w, r)
}

// inspect judges a prompt body. It returns the body to forward, or stop=true
// if it already wrote a response.
func (s *Server) inspect(w http.ResponseWriter, r *http.Request, body []byte) ([]byte, bool) {
	eng := s.cfg.Engine
	session := sessionID(r)

	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		ev := s.newEvent("prompt", r.URL.Path, session)
		ev.Severity = "medium"
		ev.Raw["note"] = "request body is not valid JSON; could not inspect"
		ev.Verdict = &event.Verdict{Mode: eng.Mode().String(), Action: "BLOCK", Effective: effective(eng.Mode(), policy.Block)}
		s.log(ev)
		if eng.Mode() == policy.Enforce {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "sentinel-x: uninspectable request body", "event_id": ev.EventID})
			return nil, true
		}
		return body, false
	}

	text := strings.Join(collectText(doc), "\n")
	findings := scan.Scan(text)
	v := eng.Evaluate(policy.Input{
		Target: "prompt", Session: session, ArgText: text, Findings: toPolicy(findings),
	})

	ev := s.verdictEvent("prompt", r.URL.Path, session, v, findings)
	if len(v.Matches) > 0 {
		s.log(ev)
	}

	switch {
	case v.Blocks():
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "blocked by sentinel-x", "rules": v.RuleIDs(), "event_id": ev.EventID,
		})
		return nil, true
	case v.Applied(policy.Throttle):
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "throttled by sentinel-x", "rules": v.RuleIDs(), "event_id": ev.EventID,
		})
		return nil, true
	case v.Applied(policy.Redact):
		red := mapText(doc, func(s string) string { return scan.RedactText(s) })
		out, err := json.Marshal(red)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "sentinel-x: redaction failed"})
			return nil, true
		}
		return out, false
	}
	return body, false
}

// ---- tool-call checker -----------------------------------------------------

type CheckRequest struct {
	Session   string         `json:"session"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	Workspace string         `json:"workspace"`
}

type CheckResponse struct {
	Decision  string         `json:"decision"`  // allow | warn | throttle | deny
	Action    string         `json:"action"`    // what the rules asked for
	Effective string         `json:"effective"` // what this mode applies
	Mode      string         `json:"mode"`
	EventID   string         `json:"event_id"`
	Matches   []policy.Match `json:"matches"`
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST only"})
		return
	}
	var req CheckRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad JSON: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Tool) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "\"tool\" is required"})
		return
	}
	if req.Session == "" {
		req.Session = sessionID(r)
	}
	if req.Workspace == "" {
		req.Workspace = s.cfg.Workspace
	}

	argText := scan.Flatten(req.Args)
	paths := scan.ExtractPaths(argText)
	for k, v := range req.Args { // explicit path-ish arguments count even if they are relative
		if str, ok := v.(string); ok && looksLikePathKey(k) && str != "" {
			paths = append(paths, str)
		}
	}
	findings := scan.Scan(argText)

	v := s.cfg.Engine.Evaluate(policy.Input{
		Target: "tool_call", Session: req.Session, Tool: req.Tool, ArgText: argText,
		Paths: paths, Workspace: req.Workspace, Findings: toPolicy(findings),
	})
	ev := s.verdictEvent("tool_call", req.Tool, req.Session, v, findings)
	ev.Action = event.Action{Category: "process", Verb: "exec"}
	if len(v.Matches) > 0 {
		s.log(ev)
	}

	resp := CheckResponse{
		Action: v.Action().String(), Effective: v.Effective().String(),
		Mode: v.Mode.String(), EventID: ev.EventID, Matches: v.Matches,
	}
	if resp.Matches == nil {
		resp.Matches = []policy.Match{}
	}
	switch eff := v.Effective(); {
	case eff >= policy.Block:
		resp.Decision = "deny"
	case eff == policy.Throttle:
		resp.Decision = "throttle"
	case eff == policy.Warn || eff == policy.Redact:
		resp.Decision = "warn"
	default:
		resp.Decision = "allow"
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- helpers ---------------------------------------------------------------

func (s *Server) newEvent(resource, value, session string) event.Event {
	ev := event.New()
	ev.Source = event.Source{Type: "agent", Sensor: "sentinel-bridge", Hostname: s.cfg.Hostname}
	ev.Action = event.Action{Category: "anomaly", Verb: "scan"}
	ev.Object = event.Object{Resource: resource, Value: value}
	ev.Detection = event.Detection{Method: "signature", Confidence: 1}
	ev.Raw = map[string]any{"session": session}
	return ev
}

func (s *Server) verdictEvent(resource, value, session string, v policy.Verdict, fs []scan.Finding) event.Event {
	ev := s.newEvent(resource, value, session)
	ev.Severity = v.Severity()
	ev.Verdict = &event.Verdict{
		Mode: v.Mode.String(), Action: v.Action().String(),
		Effective: v.Effective().String(), Rules: v.RuleIDs(),
	}
	if len(v.Matches) > 0 {
		id := v.Matches[0].RuleID
		ev.Detection.RuleID = &id
		reasons := make([]string, 0, len(v.Matches))
		for _, m := range v.Matches {
			reasons = append(reasons, m.RuleID+": "+m.Reason)
		}
		ev.Raw["reasons"] = reasons
	}
	if len(fs) > 0 {
		ev.Raw["findings"] = fs // kind/name/confidence only, never the matched text
		best := 0.0
		for _, f := range fs {
			if f.Confidence > best {
				best = f.Confidence
			}
		}
		ev.Detection.Confidence = best
	}
	return ev
}

func (s *Server) log(ev event.Event) {
	if s.cfg.Ledger == nil {
		return
	}
	if _, err := s.cfg.Ledger.Append(ev); err != nil {
		s.cfg.Logf("ledger write failed: %v", err)
	}
}

func effective(m policy.Mode, a policy.Action) string {
	if m == policy.Observe && a.Enforcing() {
		return policy.Warn.String()
	}
	return a.String()
}

func toPolicy(fs []scan.Finding) []policy.Finding {
	out := make([]policy.Finding, len(fs))
	for i, f := range fs {
		out[i] = policy.Finding{Kind: string(f.Kind), Name: f.Name, Confidence: f.Confidence}
	}
	return out
}

func sessionID(r *http.Request) string {
	if s := r.Header.Get("X-Sentinel-Session"); s != "" {
		return s
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func looksLikePathKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "path") || strings.Contains(k, "file") || strings.Contains(k, "dir") || k == "cwd"
}

// collectText returns every string stored under a prompt-carrying key.
func collectText(v any) []string {
	var out []string
	mapText(v, func(s string) string { out = append(out, s); return s })
	return out
}

// mapText returns a copy of v with fn applied to every string that sits under
// a prompt-carrying key (arrays inherit the key of their parent).
func mapText(v any, fn func(string) string) any {
	var walk func(v any, inText bool) any
	walk = func(v any, inText bool) any {
		switch t := v.(type) {
		case string:
			if inText {
				return fn(t)
			}
			return t
		case []any:
			out := make([]any, len(t))
			for i, e := range t {
				out[i] = walk(e, inText)
			}
			return out
		case map[string]any:
			out := make(map[string]any, len(t))
			for k, e := range t {
				out[k] = walk(e, inText || textKeys[k])
			}
			return out
		}
		return v
	}
	return walk(v, false)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// IsLoopback reports whether a listen address binds only to loopback.
func IsLoopback(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("bad listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return true, nil
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback(), nil
}
