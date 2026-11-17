// Package broker moves events from the ingest API to the workflow engine.
// Ingest returns as soon as the event is durable in the broker; evaluation
// happens behind it, which is what keeps the agent's critical path short.
package broker

import (
	"context"

	"github.com/sagnikc395/cerberus/internal/core"
)

// Handler evaluates one event. Returning an error leaves the event unacked, so
// it is redelivered; the evaluation workflow is idempotent in the event id, so
// a redelivery resumes rather than duplicates.
type Handler func(ctx context.Context, ev core.Event) error

// Broker is the transport. Publish is idempotent in the event id: an agent
// that retries an ingest call must not cause a second evaluation.
type Broker interface {
	Publish(ctx context.Context, ev core.Event) error
	// Subscribe starts delivering events to h and returns once consumption has
	// started. Cancelling ctx stops delivery.
	Subscribe(ctx context.Context, h Handler) error
	// Depth is how many events are waiting, for the lag metric. A broker that
	// cannot answer returns -1.
	Depth(ctx context.Context) (int64, error)
	Close() error
}
