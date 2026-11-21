# Sentinel-X

**Sentinel-X** is a single-binary, zero-dependency Go security enforcement and observability engine for local LLM endpoints, autonomous agent pipelines, and Linux hosts.

It favors **layered enforcement with zero wasted motion**: sub-millisecond deterministic YAML policies, hash-chained tamper-evident audit logs, first-class userland telemetry & containment (no cloud lock-in, no dashboard bloat), and live cross-module coordination over `sigil.sock`.

---

## Architecture

```text
[ Host / Network / Agent Runtime ]
        │
        ▼
┌─────────────────────────────────────────┐
│  1. sentinel-tap & sentinel-bridge      │  <-- Userland /proc + Parent-Dir FIM + LLM/MCP Gate
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  2. sentinel-core (Policy & Anomaly)    │  <-- Hot-reloaded YAML + behavioral baselines + session locks
└──────────────┬──────────────────────────┘
               │
      ┌────────┴────────┐
      ▼                 ▼
┌───────────┐    ┌────────────────────────┐
│ 3. Hammer │    │ 4. sigil-sync & Ledger │  <-- sigil.sock (IPC v1) + SHA-256 hash-chained JSONL
└─────┬─────┘    └──────┬─────────────────┘
      │                 │
      ▼                 ▼
[ Freeze / Sever ]  [ 5. sentinel-tui & Webhook/Telegram Alerts ]
```

### Core Modules (Pure Go Standard Library)

| Module | Package | Responsibility |
| :--- | :--- | :--- |
| **`sentinel-tap`** | `internal/tap` | Userland Linux process watcher (`/proc`, priv-esc detection), parent-directory File-Integrity Monitor (`inotify` + stat fallback catching atomic `temp -> rename` swaps, writes, creates, deletes, and `chmod`), and `/proc/net/{tcp,tcp6,udp,udp6}` outbound socket watcher (little-endian IPv4 / big-endian port decoding, inode-to-PID mapping). Includes capability-gated eBPF interface (`CAP_BPF`) for privileged native Linux hosts. |
| **`sentinel-bridge`** | `internal/bridge` | Inline reverse proxy for Ollama/OpenAI endpoints (`/api/generate`, `/api/chat`, `/v1/chat/completions`, `/v1/completions`, `/v1/messages`) stripping secrets/PII, blocking prompt injection, and throttling loops; `POST /v1/check` tool-call gate; `sentinel-x exec` wrapper; and strict-stdio `sentinel-x mcp-shim` (keeps `stdout` pure JSON-RPC 2.0). |
| **`sentinel-core`** | `internal/policy`, `internal/scan` | Strict hot-reloadable YAML rulebooks (`rules/bridge`, `rules/tap`, `rules/sigil`), DNS tunneling Shannon-entropy heuristics, dynamic per-session lock levels (`normal -> elevated -> locked`), and positive bounded-TTL operator rule overrides (max `3600s`). |
| **`sentinel-hammer`** | `internal/hammer` | Graduated containment: `WARN`, `THROTTLE`, `SEVER` (revokes session tokens & aborts live streams first; capability-gated `CAP_NET_ADMIN` `SOCK_DESTROY` fallback), and `QUARANTINE` (`SIGSTOP` PID or verified-safe `-pgid` with hard safety rails protecting PID 1, self, and ancestors). |
| **`sigil-sync`** | `internal/sigil` | Canonical versioned NDJSON IPC v1 over Unix Domain Socket (`sigil.sock`, `0600`) with `SO_PEERCRED` peer identification, non-blocking fan-out, legacy `sigil-proxy` alert normalization, and mandatory SHA-256 ledger auditing of every `control_cmd`. |
| **`sentinel-tui` & `alert`** | `internal/tui`, `internal/alert` | Zero-dependency raw-ANSI operator console (`htop` meets firewall state table) attaching to `sigil.sock`, plus deduplicated async Webhook (optional HMAC-SHA256 + AES-256-GCM encryption) and Telegram Bot API alerting. |

---

## Userland vs. Privileged Capabilities

Sentinel-X treats **unprivileged Linux userland** (including PRoot, containers, and developer workstations) as a first-class runtime:

- **Works without root:** `/proc` process & priv-esc telemetry, parent-directory FIM (mutations, renames, creates, deletes, `chmod`), `/proc/net` outbound socket tracking, LLM/MCP interception, session/stream `SEVER`, and `SIGSTOP`/`SIGCONT` `QUARANTINE`.
- **Explicit scope:** Userland FIM watches parent directories for mutations/renames/metadata changes; it does **not** claim unauthorized read observation (which requires `fanotify`/audit/eBPF on privileged Linux or tool-gate wrappers).
- **Capability-gated extensions:** Kernel eBPF tracing (`CAP_BPF`/`CAP_SYS_ADMIN`) and netlink `SOCK_DESTROY` (`CAP_NET_ADMIN`) gracefully fall back in unprivileged/PRoot environments.

---

## Quickstart

```bash
# Build single binary and run tests
make build && make test

# Validate all YAML rulebooks strictly
bin/sentinel-x lint rules

# Start the full layered daemon (defaults to observe / dry-run mode)
bin/sentinel-x run -upstream http://127.0.0.1:11434 -workspace ~/agent-workspace

# Enable active enforcement once verdicts look right
bin/sentinel-x run -mode enforce -upstream http://127.0.0.1:11434 -workspace ~/agent-workspace

# Attach the raw-ANSI operator console in another terminal
bin/sentinel-x tui

# Wrap any CLI agent command or MCP stdio server
bin/sentinel-x exec -workspace ~/agent-workspace -- ls -la
bin/sentinel-x mcp-shim -workspace ~/agent-workspace -- my-mcp-server

# Verify SHA-256 hash-chained audit ledger integrity
bin/sentinel-x verify sentinel-ledger.jsonl
```

### TUI Hotkeys (`sentinel-x tui`)
- `[j]` / `[k]` — Select quarantined PID
- `[r]` — Resume (`SIGCONT`) selected PID (audited to ledger)
- `[x]` — Terminate selected PID (audited to ledger)
- `[o]` — Apply bounded-TTL (`300s`) rule override to latest matched rule (audited to ledger)
- `[m]` — Toggle `observe` / `enforce` mode (audited to ledger)
- `[f]` — Cycle severity filter (`all` / `medium+` / `high+`)
- `[q]` — Detach cleanly

---

## Legacy Python Prototype
Earlier Python correlation scaffolding has been archived cleanly under [`legacy/`](legacy/) to keep the active Go module tree self-contained.
