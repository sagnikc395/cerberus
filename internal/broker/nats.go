package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/sagnikc395/cerberus/internal/core"
)

// Subject is where agent traffic is published.
const Subject = "cerberus.events"

// StreamName is the JetStream stream that holds it.
const StreamName = "CERBERUS"

// NATS is the durable broker: JetStream keeps the event until an engine has
// evaluated it, so a restart loses nothing that was accepted at ingest.
type NATS struct {
	conn     *nats.Conn
	js       jetstream.JetStream
	stream   jetstream.Stream
	consumer string
	ctxs     []jetstream.ConsumeContext
}

// NewNATS connects, creates the stream if it is missing, and returns the
// broker. The stream deduplicates by message id for two minutes, which is
// what makes Publish idempotent for a retrying agent.
func NewNATS(ctx context.Context, url, consumer string) (*NATS, error) {
	if url == "" {
		url = nats.DefaultURL
	}
	if consumer == "" {
		consumer = "engine"
	}
	conn, err := nats.Connect(url,
		nats.Name("cerberus"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("broker: connect to %s: %w", url, err)
	}
	js, err := jetstream.New(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("broker: jetstream: %w", err)
	}
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        StreamName,
		Subjects:    []string{Subject, Subject + ".>"},
		Retention:   jetstream.WorkQueuePolicy,
		Storage:     jetstream.FileStorage,
		Duplicates:  2 * time.Minute,
		MaxAge:      7 * 24 * time.Hour,
		Description: "agent traffic awaiting guardrail evaluation",
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("broker: create stream: %w", err)
	}
	return &NATS{conn: conn, js: js, stream: stream, consumer: consumer}, nil
}

func (b *NATS) Publish(ctx context.Context, ev core.Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	// The event id is the dedupe key, so an agent retrying an ingest call
	// after a timeout does not get a second evaluation.
	if _, err := b.js.Publish(ctx, Subject, data, jetstream.WithMsgID(ev.ID)); err != nil {
		return fmt.Errorf("broker: publish %s: %w", ev.ID, err)
	}
	return nil
}

func (b *NATS) Subscribe(ctx context.Context, h Handler) error {
	consumer, err := b.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       b.consumer,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       5 * time.Minute,
		MaxDeliver:    5,
		MaxAckPending: 256,
	})
	if err != nil {
		return fmt.Errorf("broker: create consumer: %w", err)
	}
	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		var ev core.Event
		if err := json.Unmarshal(msg.Data(), &ev); err != nil {
			// A message that will never parse must not be redelivered forever.
			_ = msg.Term()
			return
		}
		if err := h(ctx, ev); err != nil {
			_ = msg.Nak()
			return
		}
		_ = msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("broker: consume: %w", err)
	}
	b.ctxs = append(b.ctxs, cc)
	go func() {
		<-ctx.Done()
		cc.Stop()
	}()
	return nil
}

func (b *NATS) Depth(ctx context.Context) (int64, error) {
	info, err := b.stream.Info(ctx)
	if err != nil {
		return -1, err
	}
	return int64(info.State.Msgs), nil
}

func (b *NATS) Close() error {
	for _, cc := range b.ctxs {
		cc.Stop()
	}
	return b.conn.Drain()
}
