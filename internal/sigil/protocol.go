// Package sigil implements sigil-sync: bidirectional cross-module IPC over a
// Unix Domain Socket (sigil.sock) using the canonical versioned SiGiL IPC v1
// NDJSON protocol.
package sigil

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/hammer"
	"github.com/kadehood-404/sentinel-x/internal/policy"
)

const (
	ProtocolVersion = 1
	MaxFrameBytes   = 256 * 1024 // 256 KiB per NDJSON frame
)

// Message types in SiGiL IPC v1.
const (
	TypeHello            = "hello"
	TypeSubscribe        = "subscribe"
	TypeThreatSignal     = "threat_signal"
	TypeContainmentEvent = "containment_event"
	TypeVerdictEvent     = "verdict_event"
	TypeControlCmd       = "control_cmd"
	TypeControlAck       = "control_ack"
	TypeStateSnapshot    = "state_snapshot"
)

// Envelope is the top-level versioned NDJSON frame on sigil.sock.
type Envelope struct {
	V       int             `json:"v"`
	ID      string          `json:"id"`
	TS      time.Time       `json:"ts"`
	Source  string          `json:"source"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// NewEnvelope wraps payload in a fresh v1 Envelope.
func NewEnvelope(source, msgType string, payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		V:       ProtocolVersion,
		ID:      event.NewID(),
		TS:      time.Now().UTC(),
		Source:  source,
		Type:    msgType,
		Payload: raw,
	}, nil
}

// HelloPayload identifies a peer and optionally subscribes to live topics.
type HelloPayload struct {
	Subscriptions []string `json:"subscriptions,omitempty"`
	WantSnapshot  bool     `json:"want_snapshot,omitempty"`
}

// ThreatSignalPayload is sent by SiGiL Sentry or sigil-proxy to Sentinel-X.
type ThreatSignalPayload struct {
	Session         string   `json:"session"`
	Severity        string   `json:"severity"` // info | low | medium | high
	Category        string   `json:"category"` // prompt_injection | secret_leak | pii_leak | anomalous_prompt
	RuleID          string   `json:"rule_id,omitempty"`
	Confidence      float64  `json:"confidence,omitempty"`
	RecommendedLock string   `json:"recommended_lock,omitempty"` // normal | elevated | locked
	TTLSeconds      int      `json:"ttl_seconds,omitempty"`
	MatchedTypes    []string `json:"matched_types,omitempty"`
	Note            string   `json:"note,omitempty"`
}

// ContainmentEventPayload is broadcast when Sentinel-X applies containment.
type ContainmentEventPayload struct {
	EventID   string   `json:"event_id"`
	Session   string   `json:"session,omitempty"`
	PID       int      `json:"pid,omitempty"`
	Action    string   `json:"action"`    // THROTTLE | SEVER | QUARANTINE | UNFREEZE | KILL
	Effective string   `json:"effective"` // actual applied action
	Mode      string   `json:"mode"`
	RuleIDs   []string `json:"rule_ids,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// ControlCmdPayload requests an operator state change over sigil.sock.
type ControlCmdPayload struct {
	Cmd        string `json:"cmd"` // status | unfreeze | kill | set_mode | set_session_lock | override_rule | clear_override
	Session    string `json:"session,omitempty"`
	PID        int    `json:"pid,omitempty"`
	Force      bool   `json:"force,omitempty"`
	Mode       string `json:"mode,omitempty"`
	LockLevel  string `json:"lock_level,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// ControlAckPayload is returned for every control_cmd.
type ControlAckPayload struct {
	OK      bool           `json:"ok"`
	RefID   string         `json:"ref_id"`
	Message string         `json:"message"`
	State   *StateSnapshot `json:"state,omitempty"`
}

// PeerInfo describes a connected Unix socket peer.
type PeerInfo struct {
	Source      string    `json:"source"`
	PID         int       `json:"pid,omitempty"`
	UID         int       `json:"uid,omitempty"`
	ConnectedAt time.Time `json:"connected_at"`
}

// StateSnapshot represents the live daemon status pushed to TUI/CLI peers.
type StateSnapshot struct {
	Mode           string                    `json:"mode"`
	RulesCount     int                       `json:"rules_count"`
	RulesVersion   string                    `json:"rules_version"`
	LedgerSeq      uint64                    `json:"ledger_seq"`
	LedgerHash     string                    `json:"ledger_hash"`
	AlertsSent     uint64                    `json:"alerts_sent"`
	Peers          []PeerInfo                `json:"peers"`
	Sessions       []policy.SessionLockState `json:"sessions"`
	Overrides      []policy.RuleOverride     `json:"overrides"`
	Quarantined    []hammer.QuarantineRecord `json:"quarantined"`
	RecentVerdicts []event.Event             `json:"recent_verdicts"`
}

// DefaultSocketPath returns $XDG_RUNTIME_DIR/sigil.sock or /tmp/sigil-<uid>.sock.
func DefaultSocketPath() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); dir != "" {
		return filepath.Join(dir, "sigil.sock")
	}
	return fmt.Sprintf("/tmp/sigil-%d.sock", os.Getuid())
}

// DecodeFrame parses either a canonical SiGiL IPC v1 Envelope OR a legacy
// sigil-proxy audit JSON object ({"timestamp", "path", "matched_types"}) and
// normalizes legacy objects into a v1 threat_signal envelope.
func DecodeFrame(line []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Envelope{}, err
	}
	if env.V == ProtocolVersion && env.Type != "" {
		if env.ID == "" {
			env.ID = event.NewID()
		}
		if env.TS.IsZero() {
			env.TS = time.Now().UTC()
		}
		return env, nil
	}
	if env.V != 0 && env.V != ProtocolVersion {
		return Envelope{}, fmt.Errorf("unsupported sigil protocol version %d (want %d)", env.V, ProtocolVersion)
	}

	// Legacy sigil-proxy compatibility: {"timestamp", "path", "matched_types"}.
	var legacy struct {
		Timestamp    string   `json:"timestamp"`
		Path         string   `json:"path"`
		MatchedTypes []string `json:"matched_types"`
		Session      string   `json:"session"`
	}
	if err := json.Unmarshal(line, &legacy); err == nil && len(legacy.MatchedTypes) > 0 {
		cat := "secret_leak"
		sev := "medium"
		recLock := "elevated"
		for _, mt := range legacy.MatchedTypes {
			u := strings.ToUpper(mt)
			if strings.Contains(u, "INJECT") {
				cat = "prompt_injection"
				sev = "high"
				recLock = "locked"
				break
			}
			if strings.Contains(u, "EMAIL") || strings.Contains(u, "SSN") || strings.Contains(u, "PII") {
				cat = "pii_leak"
			}
		}
		sess := legacy.Session
		if sess == "" {
			sess = "sigil-proxy"
		}
		sig := ThreatSignalPayload{
			Session:         sess,
			Severity:        sev,
			Category:        cat,
			RuleID:          "sigil-proxy-legacy",
			Confidence:      0.9,
			RecommendedLock: recLock,
			TTLSeconds:      300,
			MatchedTypes:    legacy.MatchedTypes,
			Note:            "normalized legacy sigil-proxy audit alert on " + legacy.Path,
		}
		return NewEnvelope("sigil-proxy", TypeThreatSignal, sig)
	}
	return Envelope{}, fmt.Errorf("invalid sigil frame: missing v=1 and type")
}
