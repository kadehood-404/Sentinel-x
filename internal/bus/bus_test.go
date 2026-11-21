package bus

import (
	"testing"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

func TestBusPubSubAndNonBlockingDrop(t *testing.T) {
	b := New(4)
	ch, unsub := b.Subscribe(2, TopicVerdict)
	defer unsub()

	for i := 0; i < 6; i++ {
		ev := event.New()
		ev.Object.Value = "test"
		b.Publish(Message{Topic: TopicVerdict, Event: ev})
	}

	if got := b.Dropped(); got != 4 {
		t.Fatalf("dropped = %d, want 4", got)
	}
	if rec := b.Recent(10); len(rec) != 4 {
		t.Fatalf("recent len = %d, want 4", len(rec))
	}
	if len(ch) != 2 {
		t.Fatalf("buffered channel len = %d, want 2", len(ch))
	}
}
