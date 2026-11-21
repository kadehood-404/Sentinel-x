package bridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
)

func TestMCPShimStdioIsolationAndPolicyEnforcement(t *testing.T) {
	rs, err := policy.Load("../../rules/bridge")
	if err != nil {
		t.Fatal(err)
	}
	lp := filepath.Join(t.TempDir(), "mcp-ledger.jsonl")
	led, err := ledger.Open(lp)
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()

	// Fake downstream MCP server reading from srvInR and writing JSON-RPC responses to srvOutW.
	srvInR, srvInW := io.Pipe()
	srvOutR, srvOutW := io.Pipe()
	var forwardedMethods []string
	go func() {
		defer srvOutW.Close()
		sc := bufio.NewScanner(srvInR)
		for sc.Scan() {
			var req rpcEnvelope
			if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
				continue
			}
			forwardedMethods = append(forwardedMethods, req.Method)
			resp, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"ok": true},
			})
			_, _ = srvOutW.Write(append(resp, '\n'))
		}
	}()

	// Client sends:
	// 1. Safe read_file inside workspace -> allowed & forwarded to server
	// 2. Destructive bash rm -rf / -> blocked by policy -> JSON-RPC error on stdout, NEVER forwarded
	// 3. Repeated identical web_search 5 times -> 5th throttled -> JSON-RPC error on stdout
	var clientInput bytes.Buffer
	clientInput.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"src/main.go"}}}` + "\n")
	clientInput.WriteString(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bash","arguments":{"command":"rm -rf /"}}}` + "\n")
	for i := 3; i <= 7; i++ {
		b, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      i,
			"method":  "tools/call",
			"params":  map[string]any{"name": "web_search", "arguments": map[string]any{"query": "loop"}},
		})
		clientInput.Write(append(b, '\n'))
	}

	var clientOut bytes.Buffer
	var stderrLogs bytes.Buffer

	cfg := MCPConfig{
		Engine:    policy.NewEngine(policy.Enforce, rs),
		Ledger:    led,
		Workspace: "/work/agent",
		Session:   "mcp-test",
		Hostname:  "test",
		Logf: func(format string, args ...any) {
			stderrLogs.WriteString("LOG: " + format + "\n")
		},
	}

	if err := ProxyMCPStreams(context.Background(), cfg, &clientInput, &clientOut, srvInW, srvOutR); err != nil {
		t.Fatalf("ProxyMCPStreams failed: %v", err)
	}

	// Verify STRICT STDIO HYGIENE: every single line on clientOut MUST be valid JSON-RPC 2.0!
	lines := strings.Split(strings.TrimSpace(clientOut.String()), "\n")
	if len(lines) != 7 {
		t.Fatalf("expected 7 JSON-RPC responses on stdout, got %d:\n%s", len(lines), clientOut.String())
	}

	var sawAllow1, sawDeny2, sawThrottle7 bool
	for idx, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("non-JSON-RPC noise leaked to stdout on line %d: %q (%v)", idx+1, line, err)
		}
		if obj["jsonrpc"] != "2.0" {
			t.Fatalf("stdout line %d missing jsonrpc 2.0: %q", idx+1, line)
		}
		idFloat, _ := obj["id"].(float64)
		switch int(idFloat) {
		case 1:
			if obj["result"] != nil {
				sawAllow1 = true
			}
		case 2:
			if errObj, ok := obj["error"].(map[string]any); ok && int(errObj["code"].(float64)) == -32001 {
				sawDeny2 = true
			}
		case 7:
			if errObj, ok := obj["error"].(map[string]any); ok && int(errObj["code"].(float64)) == -32002 {
				sawThrottle7 = true
			}
		}
	}
	if !sawAllow1 || !sawDeny2 || !sawThrottle7 {
		t.Fatalf("missing expected verdicts: allow1=%v deny2=%v throttle7=%v\nstdout:\n%s", sawAllow1, sawDeny2, sawThrottle7, clientOut.String())
	}
	// Only 5 calls should have reached the downstream server (id 1 + ids 3,4,5,6; NOT 2 or 7).
	if len(forwardedMethods) != 5 {
		t.Fatalf("forwarded=%d, want 5 (blocked/throttled calls must not reach child server)", len(forwardedMethods))
	}
	if stderrLogs.Len() == 0 {
		t.Fatal("expected policy block/throttle diagnostics to be routed to stderr logger")
	}
	if n, err := ledger.Verify(lp); err != nil || n < 2 {
		t.Fatalf("mcp ledger verify failed: n=%d err=%v", n, err)
	}
}
