# Sentinel-X

Single-binary security runtime, policy engine, telemetry sensor (`sentinel-tap`), active containment (`sentinel-hammer`), `sigil.sock` v1 IPC bridge (`sigil-sync`), alert dispatcher, and raw-ANSI terminal console (`sentinel-tui`) for the **SiGiL** (`sigil-framework`) suite.

Built strictly on the **Go standard library** (`go.mod` has zero external dependencies).

---

## Architecture Overview

- **`sentinel-core` (`internal/policy`, `internal/scan`, `internal/event`, `internal/bus`, `internal/ledger`)**: Evaluates `prompt`, `tool_call`, `process`, `file`, `network`, and `sigil_signal` events across `observe` and `enforce` modes, tracks session lock states (`normal` -> `elevated` -> `locked`) and bounded-TTL overrides (`0 < ttl <= 3600s`), runs anomaly/entropy heuristics, publishes events over a non-blocking bus, and writes to an append-only SHA-256 hash-chained JSONL ledger (`sentinel-ledger.jsonl` by default).
- **`sentinel-bridge` (`internal/bridge`)**: Reverse proxy for Ollama / OpenAI-compatible endpoints, `POST /v1/check` tool-call gate, `/healthz`, in-flight stream/session severing, `sentinel-x exec`, and strict-stdio `sentinel-x mcp-shim`.
- **`sentinel-tap` (`internal/tap`)**: Userland-first Linux telemetry (`/proc` process & privilege-escalation watcher, parent-directory `inotify`/stat file-integrity watcher for atomic `temp -> rename` / writes / metadata mutations, and `/proc/net/{tcp,tcp6,udp,udp6}` socket watcher) with capability-gated eBPF hooks (`CAP_BPF` / `CAP_SYS_ADMIN`).
- **`sentinel-hammer` (`internal/hammer`)**: Graduated response executor (`WARN`, `THROTTLE`, userland-first `SEVER`, and `QUARANTINE` via `SIGSTOP` on PID / verified-safe `-pgid`) protected by hard safety rails (`PID <= 1`, self, parent, and ancestor exclusions).
- **`sigil-sync` (`internal/sigil`)**: Versioned NDJSON Unix domain socket protocol (`sigil.sock`, `0600`, `SO_PEERCRED`), legacy `sigil-proxy` `{timestamp, path, matched_types}` normalization, and mandatory ledger logging for every `control_cmd`.
- **`sentinel-alert` (`internal/alert`)**: Deduplicated async Webhook (HMAC-SHA256 + optional AES-256-GCM) and Telegram Bot API dispatcher.
- **`sentinel-tui` (`internal/tui`)**: Zero-dependency raw-ANSI console for live verdicts, session locks, and containment actions.

---

## Build & Rule Lint

```bash
cd ~/sentinel-x
export PATH="/home/octo/.local/bin:$PWD/bin:$PATH"
go fmt ./cmd/... ./internal/...
go vet ./...
go test -count=1 ./...
go build -o ./bin/sentinel-x ./cmd/sentinel-x
./bin/sentinel-x lint rules
```

---

## Quickstart (`observe` Mode + TUI)

1. Start the daemon in safe `observe` mode:

   ```bash
   ./bin/sentinel-x run -mode observe -rules ./rules &
   ```

2. Attach the terminal UI:

   ```bash
   ./bin/sentinel-x tui
   ```

3. Send a test tool-call check to `/v1/check`:

   ```bash
   curl -sS -X POST http://127.0.0.1:11435/v1/check \
     -H "Content-Type: application/json" \
     -d '{"session":"tui-test","target":"tool_call","tool":"bash","args":{"cmd":"cat ~/.ssh/id_rsa"}}'
   ```

### TUI Hotkeys

- `j` / `k`: Move selection
- `f`: Filter stream
- `m`: Toggle `observe` / `enforce` mode over `sigil.sock`
- `r`: Resume (`SIGCONT`) quarantined target
- `x`: Terminate quarantined target
- `o`: Apply time-bounded rule override
- `q`: Detach TUI (daemon keeps running)

---

## Ledger Verification & Clean Shutdown

Verify the SHA-256 hash chain (uses `sentinel-ledger.jsonl` by default):

```bash
./bin/sentinel-x verify
```

Stop cleanly when done:

```bash
# Press 'q' in sentinel-x tui first, then:
pkill -f "sentinel-x run"
rm -f /tmp/sigil-1000.sock
pgrep -af "sentinel-x" || echo "sentinel-x is stopped"
```

---

## Environment & Privilege Notes

- **Userland / PRoot first:** `/proc`, parent-directory FIM, session/stream severing, and `SIGSTOP`/`SIGCONT` work without privileged kernel modules or `CAP_NET_ADMIN` / `CAP_BPF`.
- **Userland FIM scope:** Watches parent directories to catch atomic renames, creates, deletes, writes, and permission/metadata changes—not raw file reads (which require kernel audit/eBPF/fanotify or wrapper enforcement).
- **MCP stdio hygiene:** `sentinel-x mcp-shim` keeps `stdout` strictly for JSON-RPC 2.0 frames and routes logs to `stderr` / the event bus / ledger.
