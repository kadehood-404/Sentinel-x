package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
	"github.com/kadehood-404/sentinel-x/internal/scan"
)

// MCPConfig configures the MCP JSON-RPC stdio policy shim.
//
// Strict Stdio Hygiene:
//   - ClientOut (typically os.Stdout) is reserved EXCLUSIVELY for valid framed
//     JSON-RPC 2.0 messages.
//   - All shim logs, policy notices, and connection errors go exclusively to
//     Logf (typically os.Stderr) and Ledger/OnVerdict — NEVER to ClientOut.
type MCPConfig struct {
	Engine    *policy.Engine
	Ledger    *ledger.Ledger
	Workspace string
	Session   string
	Hostname  string
	OnVerdict func(event.Event, policy.Verdict)
	Logf      func(string, ...any)
}

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// RunMCPShim spawns childCmd and proxies MCP JSON-RPC stdio between
// clientIn/clientOut and the child process, enforcing sentinel-core policy on
// every tools/call request.
func RunMCPShim(ctx context.Context, cfg MCPConfig, clientIn io.Reader, clientOut io.Writer, childStderr io.Writer, childCmd []string) error {
	if len(childCmd) == 0 {
		return errors.New("mcp-shim requires a child server command after --")
	}
	cmd := exec.CommandContext(ctx, childCmd[0], childCmd[1:]...)
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = childStderr
	if err := cmd.Start(); err != nil {
		return err
	}
	proxyErr := ProxyMCPStreams(ctx, cfg, clientIn, clientOut, childIn, childOut)
	_ = childIn.Close()
	waitErr := cmd.Wait()
	if proxyErr != nil {
		return proxyErr
	}
	if ctx.Err() != nil {
		return nil
	}
	return waitErr
}

// ProxyMCPStreams bridges an MCP JSON-RPC stream pair (client <-> server),
// intercepting tools/call frames. Guaranteed to write ONLY framed JSON-RPC
// bytes to clientOut.
func ProxyMCPStreams(ctx context.Context, cfg MCPConfig, clientIn io.Reader, clientOut io.Writer, serverIn io.Writer, serverOut io.Reader) error {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Session == "" {
		cfg.Session = "mcp-stdio"
	}

	var outMu sync.Mutex
	writeClient := func(payload []byte, contentLength bool) error {
		outMu.Lock()
		defer outMu.Unlock()
		return writeMCPFrame(clientOut, payload, contentLength)
	}

	// Forward server -> client JSON-RPC frames untouched.
	srvDone := make(chan error, 1)
	go func() {
		r := bufio.NewReader(serverOut)
		for {
			payload, clFramed, err := readMCPFrame(r)
			if err != nil {
				if errors.Is(err, io.EOF) {
					srvDone <- nil
					return
				}
				cfg.Logf("mcp-shim server read error: %v", err)
				srvDone <- err
				return
			}
			if err := writeClient(payload, clFramed); err != nil {
				srvDone <- err
				return
			}
		}
	}()

	// Intercept client -> server frames.
	r := bufio.NewReader(clientIn)
	for {
		if ctx.Err() != nil {
			break
		}
		payload, clFramed, err := readMCPFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			cfg.Logf("mcp-shim client read error: %v", err)
			return err
		}

		var msg rpcEnvelope
		if err := json.Unmarshal(payload, &msg); err != nil {
			cfg.Logf("mcp-shim ignoring non-JSON frame from client: %v", err)
			continue
		}

		if msg.Method == "tools/call" {
			var params mcpToolCallParams
			if err := json.Unmarshal(msg.Params, &params); err != nil {
				cfg.Logf("mcp-shim bad tools/call params: %v", err)
				if len(msg.ID) > 0 {
					errResp := makeRPCError(msg.ID, -32602, "invalid tools/call params", nil)
					_ = writeClient(errResp, clFramed)
				}
				continue
			}

			decision, ev, v := evaluateMCPTool(cfg, params)
			if decision == "deny" || decision == "throttle" {
				cfg.Logf("mcp-shim %s tool=%s rules=%v event=%s", decision, params.Name, v.RuleIDs(), ev.EventID)
				if len(msg.ID) > 0 {
					code := -32001
					text := "blocked by sentinel-x policy"
					if decision == "throttle" {
						code = -32002
						text = "throttled by sentinel-x policy"
					}
					errResp := makeRPCError(msg.ID, code, text, map[string]any{
						"decision": decision,
						"rules":    v.RuleIDs(),
						"event_id": ev.EventID,
					})
					if err := writeClient(errResp, clFramed); err != nil {
						return err
					}
				}
				continue
			}
		}

		if err := writeMCPFrame(serverIn, payload, clFramed); err != nil {
			cfg.Logf("mcp-shim server write error: %v", err)
			return err
		}
	}

	if closer, ok := serverIn.(io.Closer); ok {
		_ = closer.Close()
	}
	<-srvDone
	return nil
}

func evaluateMCPTool(cfg MCPConfig, params mcpToolCallParams) (string, event.Event, policy.Verdict) {
	argText := scan.Flatten(params.Arguments)
	paths := scan.ExtractPaths(argText)
	for k, v := range params.Arguments {
		if str, ok := v.(string); ok && looksLikePathKey(k) && str != "" {
			paths = append(paths, str)
		}
	}
	findings := scan.Scan(argText)
	for _, dom := range scan.ExtractDomains(argText) {
		findings = append(findings, scan.ScanDomain(dom)...)
	}

	v := cfg.Engine.Evaluate(policy.Input{
		Target:    "tool_call",
		Session:   cfg.Session,
		Tool:      params.Name,
		Verb:      "exec",
		ArgText:   argText,
		Paths:     paths,
		Workspace: cfg.Workspace,
		Findings:  toPolicy(findings),
	})

	ev := event.New()
	ev.Source = event.Source{Type: "agent", Sensor: "sentinel-bridge:mcp", Hostname: cfg.Hostname}
	ev.Action = event.Action{Category: "process", Verb: "exec"}
	ev.Object = event.Object{Resource: "tool_call", Value: params.Name}
	ev.Detection = event.Detection{Method: "signature", Confidence: 1}
	ev.Severity = v.Severity()
	ev.Session = cfg.Session
	ev.Verdict = &event.Verdict{
		Mode:      v.Mode.String(),
		Action:    v.Action().String(),
		Effective: v.Effective().String(),
		Rules:     v.RuleIDs(),
	}
	ev.Raw = map[string]any{"session": cfg.Session, "transport": "mcp-stdio"}
	if len(v.Matches) > 0 {
		id := v.Matches[0].RuleID
		ev.Detection.RuleID = &id
		reasons := make([]string, 0, len(v.Matches))
		for _, m := range v.Matches {
			reasons = append(reasons, m.RuleID+": "+m.Reason)
		}
		ev.Raw["reasons"] = reasons
		if cfg.Ledger != nil {
			if _, err := cfg.Ledger.Append(ev); err != nil {
				cfg.Logf("mcp-shim ledger write failed: %v", err)
			}
		}
		if cfg.OnVerdict != nil {
			cfg.OnVerdict(ev, v)
		}
	}

	switch eff := v.Effective(); {
	case eff >= policy.Block:
		return "deny", ev, v
	case eff == policy.Throttle:
		return "throttle", ev, v
	case eff == policy.Warn || eff == policy.Redact:
		return "warn", ev, v
	default:
		return "allow", ev, v
	}
}

func makeRPCError(id json.RawMessage, code int, message string, data any) []byte {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
			"data":    data,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// readMCPFrame auto-detects LSP-style Content-Length framing or NDJSON lines.
func readMCPFrame(r *bufio.Reader) ([]byte, bool, error) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && errors.Is(err, io.EOF) {
				return []byte(trimmed), false, nil
			}
			return nil, false, err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "content-length:") {
			valStr := strings.TrimSpace(trimmed[len("content-length:"):])
			n, err := strconv.Atoi(valStr)
			if err != nil || n < 0 || n > 16<<20 {
				return nil, true, fmt.Errorf("invalid Content-Length: %q", valStr)
			}
			// Drain remaining headers until blank line.
			for {
				h, err := r.ReadString('\n')
				if err != nil {
					return nil, true, err
				}
				if strings.TrimSpace(h) == "" {
					break
				}
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, true, err
			}
			return buf, true, nil
		}
		return []byte(trimmed), false, nil
	}
}

func writeMCPFrame(w io.Writer, payload []byte, contentLength bool) error {
	if contentLength {
		hdr := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload))
		if _, err := io.WriteString(w, hdr); err != nil {
			return err
		}
		_, err := w.Write(payload)
		return err
	}
	_, err := w.Write(append(payload, '\n'))
	return err
}
