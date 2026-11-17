// Package engine evaluates events. Each event is one durable workflow: the
// checks fan out as parallel checkpointed steps, the policy decides, the
// record is stored, and a risky event waits in the review queue until a human
// decides. A process that dies mid-evaluation resumes from its last
// checkpoint rather than re-running the work.
package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sagnikc395/anchora/anchora"

	"github.com/sagnikc395/cerberus/internal/broker"
	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/metrics"
	"github.com/sagnikc395/cerberus/internal/policy"
	"github.com/sagnikc395/cerberus/internal/redact"
	"github.com/sagnikc395/cerberus/internal/store"
)

// WorkflowName is the registered name of the evaluation workflow. It is part
// of the durable history, so it must not change without a migration.
const WorkflowName = "evaluate_event"

// Config wires an engine.
type Config struct {
	Anchora  *anchora.Engine
	Store    store.Store
	Policies *policy.Set
	Registry *core.Registry
	Metrics  *metrics.Metrics
	// ReviewTimeout is how long a parked event waits for a human before it is
	// marked expired and the strictest action stands.
	ReviewTimeout time.Duration
	// ReviewPoll is how often the workflow checks the queue while waiting.
	ReviewPoll time.Duration
	Escalation Escalation
	Logf       func(format string, args ...any)
}

// Outcome is the workflow's result.
type Outcome struct {
	EventID     string            `json:"event_id"`
	Action      policy.Action     `json:"action"`
	Severity    policy.Severity   `json:"severity"`
	Violations  int               `json:"violations"`
	ReviewID    string            `json:"review_id,omitempty"`
	ReviewState store.ReviewState `json:"review_state,omitempty"`
	Reviewer    string            `json:"reviewer,omitempty"`
}

// Engine is the control plane's evaluation half.
type Engine struct {
	cfg      Config
	executor *Executor
	workflow *anchora.Workflow[core.Event, Outcome]
	plans    map[string]Plan
}

// New registers the evaluation workflow and builds each agent's check plan.
// Plans are built once at startup so a policy error is a startup failure
// rather than a surprise on live traffic.
func New(cfg Config) (*Engine, error) {
	if cfg.Anchora == nil {
		return nil, errors.New("engine: an anchora engine is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("engine: a store is required")
	}
	if cfg.Policies == nil {
		return nil, errors.New("engine: a policy set is required")
	}
	if cfg.Registry == nil {
		cfg.Registry = DefaultRegistry()
	}
	if cfg.ReviewTimeout <= 0 {
		cfg.ReviewTimeout = 24 * time.Hour
	}
	if cfg.ReviewPoll <= 0 {
		cfg.ReviewPoll = 2 * time.Second
	}
	if cfg.Escalation == (Escalation{}) {
		cfg.Escalation = DefaultEscalation()
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}

	e := &Engine{cfg: cfg, plans: map[string]Plan{}}
	e.executor = NewExecutor(cfg.Metrics)
	e.executor.Escalation = cfg.Escalation

	for _, agent := range cfg.Policies.Agents() {
		p, ok := cfg.Policies.Active(agent)
		if !ok {
			continue
		}
		plan, err := buildPlan(cfg.Registry, p)
		if err != nil {
			return nil, err
		}
		e.plans[agent] = plan
	}
	// The fallback plan covers an agent with no policy: the checks still run
	// and the findings are stored, so unknown traffic is observed rather than
	// ignored.
	fallback, err := buildPlan(cfg.Registry, nil)
	if err != nil {
		return nil, err
	}
	e.plans[""] = fallback

	e.workflow = anchora.RegisterWorkflow(cfg.Anchora, WorkflowName, e.evaluate)
	return e, nil
}

// Plan returns the checks an agent runs, for the API and the CLI.
func (e *Engine) Plan(agent string) Plan {
	if plan, ok := e.plans[agent]; ok {
		return plan
	}
	return e.plans[""]
}

// Handler is the broker handler: one event, one workflow, keyed by event id so
// a redelivery joins the existing execution instead of starting a second one.
func (e *Engine) Handler() broker.Handler {
	return func(ctx context.Context, ev core.Event) error {
		_, err := e.Start(ctx, ev)
		return err
	}
}

// Start launches the evaluation workflow for an event.
func (e *Engine) Start(ctx context.Context, ev core.Event) (*anchora.Handle[Outcome], error) {
	if ev.ID == "" {
		return nil, errors.New("engine: event id is required")
	}
	return e.workflow.Start(ctx, ev, anchora.WithWorkflowID("event:"+ev.ID))
}

// Evaluate runs an event to completion and returns the outcome. The API uses
// it for the synchronous path an agent can choose when it wants the verdict
// before it acts.
func (e *Engine) Evaluate(ctx context.Context, ev core.Event) (Outcome, error) {
	h, err := e.Start(ctx, ev)
	if err != nil {
		return Outcome{}, err
	}
	return h.Result(ctx)
}

// evaluate is the workflow. Every engine call it makes is checkpointed, so the
// comments below describe what survives a crash at each point.
func (e *Engine) evaluate(ctx *anchora.Context, ev core.Event) (Outcome, error) {
	started := time.Now()

	// The session rollup is advanced exactly once per event: it is a write,
	// and a replay must not count the same tokens twice.
	session, err := anchora.Step(ctx, "advance_session", func(sc anchora.StepCtx) (core.SessionState, error) {
		return e.cfg.Store.AdvanceSession(sc, ev)
	}, anchora.Retry(5, 200*time.Millisecond, 2), anchora.Timeout(10*time.Second))
	if err != nil {
		return Outcome{}, err
	}
	ev.Session = session

	plan := e.Plan(ev.AgentID)
	// Each check is an anchora.Go step: parallel within its tier, individually
	// retried and timed out, and replayed from its checkpoint after a crash.
	executor := *e.executor
	executor.Spawn = func(_ context.Context, name string, t Task) Await {
		future := anchora.Go(ctx, name, func(sc anchora.StepCtx) (core.Result, error) {
			return t(sc)
		}, anchora.Retry(2, 100*time.Millisecond, 2), anchora.Timeout(45*time.Second))
		return func(c context.Context) (core.Result, error) { return future.Wait(c) }
	}
	results := executor.Run(workflowContext{ctx}, plan, ev)

	active, _ := e.cfg.Policies.Active(ev.AgentID)
	decision := policy.Decision{Action: policy.ActionAllow}
	if active != nil {
		decision = active.Evaluate(ev, results)
	} else {
		// No policy for this agent: record the findings under the convention
		// that an unflagged event is allowed and a flagged one is logged.
		decision.Agent = ev.AgentID
		for _, r := range results {
			if r.Verdict.Flagged() {
				decision.Action = policy.ActionLog
				decision.Violations = append(decision.Violations, policy.Violation{
					Check: r.Check, Version: r.Version, Label: r.Verdict.Label,
					Score: r.Verdict.Score, Action: policy.ActionLog, Rule: -1,
					Severity: policy.SeverityLow, Notes: "no policy loaded for this agent",
					Evidence: r.Verdict.Evidence,
				})
			}
		}
	}

	// Redaction happens before the store write, inside the workflow, so the
	// raw event exists only in memory during evaluation.
	redacted, masked := redact.Event(ev)
	safeResults := redact.Results(results)

	evaluation := store.Evaluation{
		EventID:    ev.ID,
		Agent:      ev.AgentID,
		SessionID:  ev.SessionID,
		Kind:       ev.Kind,
		ReceivedAt: ev.CreatedAt,
		DecidedAt:  time.Now().UTC(),
		Event:      redacted,
		Results:    safeResults,
		Decision:   decision,
		Masked:     masked,
		Latency:    time.Since(started),
		WorkflowID: ctx.WorkflowID(),
	}
	if _, err := anchora.Step(ctx, "persist", func(sc anchora.StepCtx) (bool, error) {
		return true, e.cfg.Store.SaveEvaluation(sc, evaluation)
	}, anchora.Retry(5, 200*time.Millisecond, 2), anchora.Timeout(15*time.Second)); err != nil {
		return Outcome{}, err
	}

	e.observe(ev, decision, masked, time.Since(started))

	out := Outcome{
		EventID:    ev.ID,
		Action:     decision.Action,
		Severity:   decision.Severity,
		Violations: len(decision.Violations),
	}
	if !policy.NeedsReview(decision.Action) {
		return out, nil
	}

	// The review queue is a wait state: the workflow parks here, and the event
	// is held until a human decides or the wait expires. The queue id is
	// derived from the event id, so a replay re-uses the same queue item.
	reviewID := "review:" + ev.ID
	if _, err := anchora.Step(ctx, "enqueue_review", func(sc anchora.StepCtx) (bool, error) {
		return true, e.cfg.Store.EnqueueReview(sc, store.Review{
			ID:         reviewID,
			EventID:    ev.ID,
			Agent:      ev.AgentID,
			Action:     decision.Action,
			Severity:   decision.Severity,
			State:      store.ReviewPending,
			CreatedAt:  time.Now().UTC(),
			Violations: decision.Violations,
			Event:      redacted,
		})
	}, anchora.Retry(5, 200*time.Millisecond, 2), anchora.Timeout(15*time.Second)); err != nil {
		return Outcome{}, err
	}
	out.ReviewID = reviewID

	review, err := e.waitForReview(ctx, reviewID)
	if err != nil {
		return out, err
	}
	out.ReviewState = review.State
	out.Reviewer = review.Reviewer
	if e.cfg.Metrics != nil {
		e.cfg.Metrics.ReviewDecisions.WithLabelValues(ev.AgentID, string(review.State)).Inc()
	}
	return out, nil
}

// waitForReview polls the queue from inside the workflow. Each poll is a
// checkpointed step and each gap is a durable timer, so the wait survives a
// restart of every process involved without losing its place.
func (e *Engine) waitForReview(ctx *anchora.Context, reviewID string) (store.Review, error) {
	deadline := time.Now().Add(e.cfg.ReviewTimeout)
	for attempt := 0; ; attempt++ {
		review, err := anchora.Step(ctx, "poll_review", func(sc anchora.StepCtx) (store.Review, error) {
			return e.cfg.Store.Review(sc, reviewID)
		}, anchora.Retry(5, 200*time.Millisecond, 2), anchora.Timeout(10*time.Second))
		if err != nil {
			return store.Review{}, err
		}
		if review.State != store.ReviewPending {
			return review, nil
		}
		now, err := anchora.Now(ctx)
		if err != nil {
			return store.Review{}, err
		}
		if now.After(deadline) {
			// Nobody came. The strictest action already applied; the queue item
			// is marked so it stops showing up as waiting work.
			expired, err := anchora.Step(ctx, "expire_review", func(sc anchora.StepCtx) (store.Review, error) {
				r, err := e.cfg.Store.DecideReview(sc, reviewID, store.ReviewDecision{
					State:    store.ReviewExpired,
					Reviewer: "system",
					Notes:    fmt.Sprintf("no decision within %s", e.cfg.ReviewTimeout),
				})
				if err != nil {
					// A reviewer who decided in the same instant wins the race.
					if existing, lookupErr := e.cfg.Store.Review(sc, reviewID); lookupErr == nil && existing.State != store.ReviewPending {
						return existing, nil
					}
					return store.Review{}, err
				}
				return r, nil
			}, anchora.Retry(3, time.Second, 2), anchora.Timeout(10*time.Second))
			if err != nil {
				return store.Review{}, err
			}
			return expired, nil
		}
		if err := anchora.Sleep(ctx, e.pollInterval(attempt)); err != nil {
			return store.Review{}, err
		}
	}
}

// pollInterval backs off: a reviewer who is already looking at the queue is
// answered in seconds, and an item that sits overnight is not polled all
// night at the same rate.
func (e *Engine) pollInterval(attempt int) time.Duration {
	d := e.cfg.ReviewPoll << min(attempt, 6)
	if max := 2 * time.Minute; d > max {
		return max
	}
	return d
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// workflowContext adapts a workflow's cancellation to context.Context. The
// executor only observes cancellation through it; every side effect still runs
// inside a step with the step's own context.
type workflowContext struct{ c *anchora.Context }

func (workflowContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (w workflowContext) Done() <-chan struct{}     { return w.c.Done() }
func (w workflowContext) Err() error                { return w.c.Err() }
func (workflowContext) Value(key any) any           { return nil }

func (e *Engine) observe(ev core.Event, d policy.Decision, masked int, latency time.Duration) {
	m := e.cfg.Metrics
	if m == nil {
		return
	}
	m.EventsEvaluated.WithLabelValues(ev.AgentID, string(d.Action)).Inc()
	m.EvaluationLatency.WithLabelValues(ev.AgentID).Observe(latency.Seconds())
	severity := string(d.Severity)
	if severity == "" {
		severity = "none"
	}
	m.PolicyActions.WithLabelValues(ev.AgentID, fmt.Sprint(d.PolicyVersion), string(d.Action), severity).Inc()
	for _, v := range d.Violations {
		m.Violations.WithLabelValues(ev.AgentID, v.Check, string(v.Action)).Inc()
	}
	if masked > 0 {
		m.Redactions.Add(float64(masked))
	}
}
