package bridge_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/kadehood-404/sentinel-x/internal/bridge"
	"github.com/kadehood-404/sentinel-x/internal/policy"
)

func writeTestRuleset(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ruleYAML := `rules:
  - id: prompt-loop
    description: Same prompt sent repeatedly (runaway agent loop)
    target: prompt
    severity: medium
    action: THROTTLE
    match:
      repeat:
        count: 8
        window: 60

  - id: tool-outside-workspace
    description: Tool call touches a path outside the agent workspace
    target: tool_call
    severity: high
    action: BLOCK
    match:
      outside_workspace: true

  - id: tool-destructive-shell
    description: Destructive shell command
    target: tool_call
    severity: high
    action: BLOCK
    match:
      tool: [shell, bash, sh, zsh, fish, exec, run_command, run_shell, terminal, execute, cmd, python]
      arg_regex: '(?:^|[;&|()]|\s)rm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*\s+-[a-zA-Z]*[fF][a-zA-Z]*|-[a-zA-Z]*[fF][a-zA-Z]*\s+-[a-zA-Z]*[rR][a-zA-Z]*|-[a-zA-Z]*(?:[rR][a-zA-Z]*[fF]|[fF][a-zA-Z]*[rR])[a-zA-Z]*)(?:\s+--)?\s+(/|~|\$HOME|\$\{HOME\}|\.\.)|\bmkfs(?:\.[a-z0-9]+)?\b|\bdd\s+if=\S+\s+of=/dev/|:\(\)\s*\{|chmod\s+(?:-[a-zA-Z]*R[a-zA-Z]*\s+)?777\s+/'
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(ruleYAML), 0o600); err != nil {
		t.Fatalf("write rules.yaml: %v", err)
	}
	return dir
}

func TestPromptLoopThrottlesSameMintedSession(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"ok","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer upstream.Close()

	upURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	rs, err := policy.Load(writeTestRuleset(t))
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}

	eng := policy.NewEngine(policy.Enforce, rs)
	srv := bridge.New(bridge.Config{
		Upstream:  upURL,
		Engine:    eng,
		Workspace: t.TempDir(),
		Hostname:  "test-host",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 1. Mint a daemon session token.
	sessReq, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/session", nil)
	if err != nil {
		t.Fatalf("new session request: %v", err)
	}
	sessResp, err := http.DefaultClient.Do(sessReq)
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	defer sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 from /v1/session, got %d", sessResp.StatusCode)
	}

	var minted struct {
		Session string `json:"session"`
	}
	if err := json.NewDecoder(sessResp.Body).Decode(&minted); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if minted.Session == "" {
		t.Fatal("expected non-empty minted session token")
	}

	// 2. Send 9 identical chat prompts using the same Bearer token.
	// With repeat.count = 8, requests 1..7 pass (200) and requests 8..9 hit 429.
	payload := []byte(`{"messages":[{"role":"user","content":"hello there"}]}`)
	for i := 1; i <= 9; i++ {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("build request %d: %v", i, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+minted.Session)
		// Spoofed header must not bypass or fragment the minted session token.
		req.Header.Set("X-Sentinel-Session", "spoofed-session")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()

		if i < 8 && resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200 before repeat threshold, got %d", i, resp.StatusCode)
		}
		if i >= 8 && resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("request %d: expected 429 on prompt-loop threshold, got %d", i, resp.StatusCode)
		}
	}
}

func TestToolAliasAndIFSShellNormalizationBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}

	rs, err := policy.Load(writeTestRuleset(t))
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}

	srv := bridge.New(bridge.Config{
		Upstream:  upURL,
		Engine:    policy.NewEngine(policy.Enforce, rs),
		Workspace: t.TempDir(),
		Hostname:  "test-host",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	cases := []struct {
		name string
		body string
	}{
		{
			name: "terminal alias fork bomb",
			body: `{"tool":"terminal","args":{"cmd":":(){ :|:& };:"}}`,
		},
		{
			name: "python alias fork bomb",
			body: `{"tool":"python","args":{"cmd":":(){ :|:& };:"}}`,
		},
		{
			name: "ifs obfuscated rm tilde",
			body: `{"tool":"execute","args":{"cmd":"rm -r${IFS}-f${IFS}~"}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/check", bytes.NewBufferString(tc.body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			defer resp.Body.Close()

			var out bridge.CheckResponse
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if out.Decision != "deny" {
				t.Fatalf("expected decision=deny for %s, got %q (matches=%+v)", tc.name, out.Decision, out.Matches)
			}
		})
	}
}
