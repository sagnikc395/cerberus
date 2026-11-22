// Package client is the Go SDK an agent uses to send its traffic to cerberus.
//
// Two shapes of call, matching the two ways an agent can use a guardrail:
//
//	Report  - fire and forget. The call returns as soon as the control plane
//	          has the event; evaluation happens behind it. Use it for anything
//	          the agent is not going to wait on.
//	Check   - synchronous. The call returns the action the policy decided, so
//	          the agent can honour a block before it acts.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
)

// Event is the traffic an agent reports. It is re-exported so an SDK user does
// not import an internal package.
type Event = core.Event

// Document is untrusted context that reached the model.
type Document = core.Document

// ToolCall is one tool invocation.
type ToolCall = core.ToolCall

// Usage is the token spend attributed to an event.
type Usage = core.Usage

// Event kinds.
const (
	KindPrompt     = core.KindPrompt
	KindCompletion = core.KindCompletion
	KindToolCall   = core.KindToolCall
	KindToolResult = core.KindToolResult
)

// Decision is what the control plane decided about an event.
type Decision struct {
	EventID     string `json:"event_id"`
	Action      string `json:"action"`
	Severity    string `json:"severity,omitempty"`
	Violations  int    `json:"violations,omitempty"`
	ReviewID    string `json:"review_id,omitempty"`
	ReviewState string `json:"review_state,omitempty"`
	Reviewer    string `json:"reviewer,omitempty"`
}

// Blocked reports whether the agent should stop rather than act. An agent that
// ignores this is running without a guardrail, however many checks fired.
func (d Decision) Blocked() bool {
	switch d.Action {
	case "block", "quarantine", "require_human_approval":
		return true
	}
	return false
}

// Client talks to a cerberus control plane.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// Option configures a client.
type Option func(*Client)

// WithToken sets the bearer token the control plane requires.
func WithToken(token string) Option { return func(c *Client) { c.token = token } }

// WithHTTPClient replaces the HTTP client, for timeouts, proxies or tracing.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// New returns a client for the control plane at baseURL.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{baseURL: baseURL, http: &http.Client{Timeout: 10 * time.Second}}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Report sends an event without waiting for its evaluation. The returned id is
// what a later lookup or review refers to.
func (c *Client) Report(ctx context.Context, ev Event) (string, error) {
	d, err := c.send(ctx, ev, false)
	return d.EventID, err
}

// Check sends an event and waits for the action. A context deadline is the
// agent's own budget for the call: on timeout the event is still evaluated,
// and the agent decides what to do without a verdict.
func (c *Client) Check(ctx context.Context, ev Event) (Decision, error) {
	return c.send(ctx, ev, true)
}

type request struct {
	Event
	Wait bool `json:"wait,omitempty"`
}

type response struct {
	EventID  string    `json:"event_id"`
	Accepted bool      `json:"accepted"`
	Outcome  *Decision `json:"outcome,omitempty"`
}

func (c *Client) send(ctx context.Context, ev Event, wait bool) (Decision, error) {
	body, err := json.Marshal(request{Event: ev, Wait: wait})
	if err != nil {
		return Decision{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("cerberus: report event: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Decision{}, err
	}
	if resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(payload, &apiErr)
		if apiErr.Error == "" {
			apiErr.Error = resp.Status
		}
		return Decision{}, fmt.Errorf("cerberus: %s: %s", resp.Status, apiErr.Error)
	}
	var out response
	if err := json.Unmarshal(payload, &out); err != nil {
		return Decision{}, err
	}
	if wait && out.Outcome == nil {
		return Decision{}, fmt.Errorf("cerberus: missing decision for event %s", out.EventID)
	}
	if out.Outcome != nil {
		out.Outcome.EventID = out.EventID
		return *out.Outcome, nil
	}
	return Decision{EventID: out.EventID, Action: "accepted"}, nil
}
