package broker

import (
	"context"
	"errors"
	"sync"

	"github.com/sagnikc395/cerberus/internal/core"
)

// InProc is a buffered in-process broker. It is what `make demo` and the
// tests run on, and it is a real implementation rather than a stub: the same
// delivery contract, the same idempotency, no network.
type InProc struct {
	events chan core.Event

	mu   sync.Mutex
	seen map[string]struct{}
	errs chan error
	done bool
}

// NewInProc returns a broker that buffers up to size events.
func NewInProc(size int) *InProc {
	if size <= 0 {
		size = 1024
	}
	return &InProc{
		events: make(chan core.Event, size),
		seen:   map[string]struct{}{},
		errs:   make(chan error, size),
	}
}

func (b *InProc) Publish(ctx context.Context, ev core.Event) error {
	b.mu.Lock()
	if b.done {
		b.mu.Unlock()
		return errors.New("broker: closed")
	}
	if _, dup := b.seen[ev.ID]; dup {
		b.mu.Unlock()
		return nil
	}
	b.seen[ev.ID] = struct{}{}
	b.mu.Unlock()

	select {
	case b.events <- ev:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *InProc) Subscribe(ctx context.Context, h Handler) error {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-b.events:
				if !ok {
					return
				}
				if err := h(ctx, ev); err != nil {
					select {
					case b.errs <- err:
					default:
					}
				}
			}
		}
	}()
	return nil
}

// Errors exposes handler failures, which the demo prints and the tests assert
// on. A production broker surfaces these as redeliveries instead.
func (b *InProc) Errors() <-chan error { return b.errs }

func (b *InProc) Depth(context.Context) (int64, error) { return int64(len(b.events)), nil }

func (b *InProc) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.done {
		b.done = true
		close(b.events)
	}
	return nil
}
