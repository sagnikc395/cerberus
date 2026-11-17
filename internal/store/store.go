// Package store persists evaluated events, the review queue, and the rolling
// session state the cost checks read. Everything written here has already been
// through internal/redact.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/policy"
)

// ErrNotFound is returned by the lookups.
var ErrNotFound = errors.New("store: not found")

// Evaluation is the durable record of one event's trip through the engine.
type Evaluation struct {
	EventID    string          `json:"event_id"`
	Agent      string          `json:"agent"`
	SessionID  string          `json:"session_id,omitempty"`
	Kind       core.Kind       `json:"kind"`
	ReceivedAt time.Time       `json:"received_at"`
	DecidedAt  time.Time       `json:"decided_at"`
	Event      core.Event      `json:"event"`
	Results    []core.Result   `json:"results"`
	Decision   policy.Decision `json:"decision"`
	// Masked is how many values the redactor replaced before this record was
	// written. It is reported as a metric: a sudden drop usually means a
	// detector broke, not that the traffic got cleaner.
	Masked  int           `json:"masked"`
	Latency time.Duration `json:"latency"`
	// WorkflowID ties the record back to the durable execution that produced it.
	WorkflowID string `json:"workflow_id,omitempty"`
}

// ReviewState is where a queued item stands.
type ReviewState string

const (
	ReviewPending  ReviewState = "pending"
	ReviewApproved ReviewState = "approved"
	ReviewRejected ReviewState = "rejected"
	ReviewExpired  ReviewState = "expired"
)

// Label is a reviewer's judgement about one check's verdict. These are the
// labels the eval harness consumes.
type Label string

const (
	// LabelTruePositive means the check was right to fire.
	LabelTruePositive Label = "true_positive"
	// LabelFalsePositive means it fired on benign traffic.
	LabelFalsePositive Label = "false_positive"
	// LabelUnsure keeps the item out of the eval set.
	LabelUnsure Label = "unsure"
)

// CheckLabel is one reviewer label attached to one check's verdict.
type CheckLabel struct {
	Check   string  `json:"check"`
	Version string  `json:"check_version"`
	Label   Label   `json:"label"`
	Score   float64 `json:"score"`
}

// Review is a queued item waiting for a human.
type Review struct {
	ID         string             `json:"id"`
	EventID    string             `json:"event_id"`
	Agent      string             `json:"agent"`
	Action     policy.Action      `json:"action"`
	Severity   policy.Severity    `json:"severity"`
	State      ReviewState        `json:"state"`
	CreatedAt  time.Time          `json:"created_at"`
	DecidedAt  *time.Time         `json:"decided_at,omitempty"`
	Reviewer   string             `json:"reviewer,omitempty"`
	Notes      string             `json:"notes,omitempty"`
	Violations []policy.Violation `json:"violations"`
	Labels     []CheckLabel       `json:"labels,omitempty"`
	// Event is the redacted event, so a reviewer can see what fired without
	// leaving the queue.
	Event core.Event `json:"event"`
}

// Decision is what a reviewer submits.
type ReviewDecision struct {
	State    ReviewState  `json:"state"`
	Reviewer string       `json:"reviewer"`
	Notes    string       `json:"notes,omitempty"`
	Labels   []CheckLabel `json:"labels,omitempty"`
}

// EventFilter narrows a listing of evaluations.
type EventFilter struct {
	Agent       string
	Since       time.Time
	FlaggedOnly bool
	Limit       int
}

// ReviewFilter narrows a listing of the queue.
type ReviewFilter struct {
	Agent string
	State ReviewState
	Limit int
}

// LabelStats is the reviewer-derived accuracy of one check version: the share
// of its flags a human confirmed.
type LabelStats struct {
	Check          string  `json:"check"`
	Version        string  `json:"check_version"`
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	Unsure         int     `json:"unsure"`
	Precision      float64 `json:"precision"`
}

// Store is the persistence the engine needs. Both implementations are safe for
// concurrent use.
type Store interface {
	SaveEvaluation(ctx context.Context, e Evaluation) error
	Evaluation(ctx context.Context, eventID string) (Evaluation, error)
	ListEvaluations(ctx context.Context, f EventFilter) ([]Evaluation, error)

	EnqueueReview(ctx context.Context, r Review) error
	Review(ctx context.Context, id string) (Review, error)
	ListReviews(ctx context.Context, f ReviewFilter) ([]Review, error)
	DecideReview(ctx context.Context, id string, d ReviewDecision) (Review, error)

	// AdvanceSession folds an event into its session's rolling state and
	// returns the state as of that event, which is what the cost checks read.
	AdvanceSession(ctx context.Context, ev core.Event) (core.SessionState, error)

	// LabelStats reports reviewer-confirmed precision per check version.
	LabelStats(ctx context.Context, since time.Time) ([]LabelStats, error)

	Close() error
}

// recentCallWindow is how many prior tool calls a session carries. It bounds
// what the repeated-call check can see, and what the store has to keep.
const recentCallWindow = 20
