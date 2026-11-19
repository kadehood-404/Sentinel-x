// Package event defines the canonical Sentinel-X event record.
//
// The shape follows docs/event_schema.json. Every record that reaches the
// audit ledger is one of these, so there is no hidden logic: if it was
// decided, it is written down in this format.
package event

import (
	"crypto/rand"
	"fmt"
	"time"
)

type Source struct {
	Type     string `json:"type"` // network | host | app | agent
	Sensor   string `json:"sensor"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip,omitempty"`
}

type Action struct {
	Category string `json:"category"` // network | auth | file | process | anomaly
	Verb     string `json:"verb"`     // connect | read | write | exec | scan
}

type Object struct {
	Resource string `json:"resource"` // ip | domain | file | process | prompt | tool_call
	Value    string `json:"value"`
}

type Detection struct {
	Method     string  `json:"method"` // raw | signature | heuristic | anomaly
	RuleID     *string `json:"rule_id"`
	Confidence float64 `json:"confidence"`
}

// Verdict records what policy decided and what was actually done about it.
type Verdict struct {
	Mode      string   `json:"mode"`      // observe | enforce
	Action    string   `json:"action"`    // what the rules asked for
	Effective string   `json:"effective"` // what was applied in this mode
	Rules     []string `json:"rules"`
}

type Event struct {
	EventID   string         `json:"event_id"`
	Timestamp time.Time      `json:"timestamp"`
	Source    Source         `json:"source"`
	Action    Action         `json:"action"`
	Object    Object         `json:"object"`
	Detection Detection      `json:"detection"`
	Severity  string         `json:"severity"` // info | low | medium | high
	Verdict   *Verdict       `json:"verdict,omitempty"`
	Raw       map[string]any `json:"raw,omitempty"`
}

// New returns an event with a fresh ID and timestamp.
func New() Event {
	return Event{EventID: newID(), Timestamp: time.Now().UTC(), Severity: "info"}
}

// newID returns a random RFC 4122 version 4 UUID.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable in any useful way.
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
