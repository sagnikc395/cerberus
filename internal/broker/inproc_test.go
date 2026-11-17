package broker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
)

func TestPublishIsIdempotentInTheEventID(t *testing.T) {
	b := NewInProc(8)
	defer b.Close()
	ctx := context.Background()

	var mu sync.Mutex
	var seen []string
	if err := b.Subscribe(ctx, func(_ context.Context, ev core.Event) error {
		mu.Lock()
		seen = append(seen, ev.ID)
		mu.Unlock()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := b.Publish(ctx, core.Event{ID: "ev-1", AgentID: "a", Kind: core.KindPrompt}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the event was never delivered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Errorf("delivered %d times, want once: %v", len(seen), seen)
	}
}

func TestDepthReportsWaitingEvents(t *testing.T) {
	b := NewInProc(8)
	defer b.Close()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := b.Publish(ctx, core.Event{ID: string(rune('a' + i)), AgentID: "a", Kind: core.KindPrompt}); err != nil {
			t.Fatal(err)
		}
	}
	depth, err := b.Depth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if depth != 3 {
		t.Errorf("depth = %d, want 3", depth)
	}
}
