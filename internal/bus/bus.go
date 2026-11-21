// Package bus provides a non-blocking in-process pub/sub event bus so
// sentinel-tap, sentinel-bridge, sentinel-hammer, sigil-sync, alert, and
// sentinel-tui share live events without polling disk.
package bus

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

type Topic string

const (
	TopicTelemetry   Topic = "telemetry"
	TopicVerdict     Topic = "verdict"
	TopicContainment Topic = "containment"
	TopicThreat      Topic = "threat_signal"
	TopicControl     Topic = "control"
)

type Message struct {
	Topic Topic
	Time  time.Time
	Event event.Event
	Extra any
}

type subscriber struct {
	id     uint64
	topics map[Topic]bool // empty means all topics
	ch     chan Message
}

// Bus fans out messages to bounded subscriber queues without ever blocking
// publishers. If a slow subscriber's buffer is full, the message is dropped
// for that subscriber and counted in Dropped().
type Bus struct {
	mu      sync.RWMutex
	nextID  uint64
	subs    map[uint64]*subscriber
	recent  []event.Event
	maxHist int
	dropped atomic.Uint64
}

// New creates a Bus retaining up to maxHistory recent verdict/containment events.
func New(maxHistory int) *Bus {
	if maxHistory <= 0 {
		maxHistory = 256
	}
	return &Bus{
		subs:    make(map[uint64]*subscriber),
		recent:  make([]event.Event, 0, maxHistory),
		maxHist: maxHistory,
	}
}

// Subscribe returns a buffered channel receiving messages for topics (or all
// topics when none are specified) and an unsubscribe function.
func (b *Bus) Subscribe(bufSize int, topics ...Topic) (<-chan Message, func()) {
	if bufSize <= 0 {
		bufSize = 64
	}
	tset := make(map[Topic]bool, len(topics))
	for _, t := range topics {
		tset[t] = true
	}
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	sub := &subscriber{id: id, topics: tset, ch: make(chan Message, bufSize)}
	b.subs[id] = sub
	b.mu.Unlock()

	var once sync.Once
	unsub := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, id)
			b.mu.Unlock()
		})
	}
	return sub.ch, unsub
}

// Publish dispatches msg to all matching subscribers without blocking.
func (b *Bus) Publish(msg Message) {
	if msg.Time.IsZero() {
		msg.Time = time.Now().UTC()
	}
	b.mu.Lock()
	if msg.Event.EventID != "" && (msg.Topic == TopicVerdict || msg.Topic == TopicContainment || msg.Topic == TopicControl) {
		if len(b.recent) >= b.maxHist {
			copy(b.recent, b.recent[1:])
			b.recent[len(b.recent)-1] = msg.Event
		} else {
			b.recent = append(b.recent, msg.Event)
		}
	}
	subs := make([]*subscriber, 0, len(b.subs))
	for _, s := range b.subs {
		if len(s.topics) == 0 || s.topics[msg.Topic] {
			subs = append(subs, s)
		}
	}
	b.mu.Unlock()

	for _, s := range subs {
		select {
		case s.ch <- msg:
		default:
			b.dropped.Add(1)
		}
	}
}

// Recent returns up to n most recent recorded events (newest last).
func (b *Bus) Recent(n int) []event.Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if n <= 0 || n > len(b.recent) {
		n = len(b.recent)
	}
	out := make([]event.Event, n)
	copy(out, b.recent[len(b.recent)-n:])
	return out
}

// Dropped returns the total number of messages dropped due to full subscriber queues.
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }
