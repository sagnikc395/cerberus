package engine

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/metrics"
)

// Skip reasons recorded on a result and on the skipped-checks metric.
const (
	skipNotApplicable = "not_applicable"
	skipTierNotNeeded = "tier_not_escalated"
)

// Task runs one check and returns its result.
type Task func(ctx context.Context) (core.Result, error)

// Await blocks for a task started by a Spawner.
type Await func(ctx context.Context) (core.Result, error)

// Spawner starts a task. The plain executor starts a goroutine; the durable
// engine passes a spawner backed by anchora.Go, which makes every check a
// checkpointed step with its own retries, timeout and idempotency key.
type Spawner func(ctx context.Context, name string, t Task) Await

// Escalation decides whether the next, more expensive tier is worth running.
type Escalation struct {
	// AmbiguousFrom is the score at which a non-flagging verdict is still
	// interesting enough to pay for the next tier.
	AmbiguousFrom float64
	// Always escalates regardless of what the cheap tiers found. Useful while
	// a new detector is being measured against the old one.
	Always bool
}

// DefaultEscalation runs the expensive tiers when a cheap check flagged, or
// when one landed in the band just below its threshold.
func DefaultEscalation() Escalation { return Escalation{AmbiguousFrom: 0.25} }

// escalate reports whether to run the next tier given what has been seen.
func (e Escalation) escalate(results []core.Result) (bool, string) {
	if e.Always {
		return true, "escalation.always"
	}
	for _, r := range results {
		if r.Skipped {
			continue
		}
		if r.Err != "" {
			// A cheap check that failed leaves a hole; let the next tier look.
			return true, "check_error:" + r.Check
		}
		if r.Verdict.Flagged() {
			return true, "flagged:" + r.Check
		}
		if e.AmbiguousFrom > 0 && r.Verdict.Score >= e.AmbiguousFrom {
			return true, "ambiguous:" + r.Check
		}
	}
	return false, ""
}

// Executor runs a plan's checks tier by tier. It is the same code path in the
// durable engine and in the eval harness; only the spawner differs.
type Executor struct {
	Metrics    *metrics.Metrics
	Escalation Escalation
	// TierTimeout bounds one check run per tier. A check that overruns is
	// recorded as an error rather than holding the event.
	TierTimeout map[core.Tier]time.Duration
	// Spawn is how a check is started. Nil means goroutines.
	Spawn Spawner
}

// NewExecutor returns an executor with the default tier timeouts.
func NewExecutor(m *metrics.Metrics) *Executor {
	return &Executor{
		Metrics:    m,
		Escalation: DefaultEscalation(),
		TierTimeout: map[core.Tier]time.Duration{
			core.TierRegex:      2 * time.Second,
			core.TierClassifier: 5 * time.Second,
			core.TierLLMJudge:   30 * time.Second,
		},
	}
}

// Run evaluates ev against the plan and returns one result per check,
// including the ones that were skipped: a missing result and a clean result
// must not look the same to a policy or to the eval harness.
func (x *Executor) Run(ctx context.Context, plan Plan, ev core.Event) []core.Result {
	results := make([]core.Result, 0, len(plan.Checks))
	for i, group := range tiers(plan.Checks) {
		if i > 0 {
			if ok, _ := x.Escalation.escalate(results); !ok {
				// The tier is not worth its cost on this event. Checks that
				// sample themselves still run: they are not looking for what
				// the cheap tiers found.
				var independent []core.Check
				for _, c := range group {
					if ind, ok := c.(core.Independent); ok && ind.RunsIndependently() {
						independent = append(independent, c)
						continue
					}
					results = append(results, core.Result{
						Check: c.Name(), Version: c.Version(), Tier: c.Tier(),
						Skipped: true, Err: skipTierNotNeeded,
					})
					x.observeSkip(c, skipTierNotNeeded)
				}
				if len(independent) == 0 {
					continue
				}
				group = independent
			}
		}
		if x.Metrics != nil && len(group) > 0 {
			x.Metrics.TierRuns.WithLabelValues(group[0].Tier().String()).Inc()
		}
		results = append(results, x.runTier(ctx, group, ev)...)
	}
	return results
}

func (x *Executor) runTier(ctx context.Context, group []core.Check, ev core.Event) []core.Result {
	type pending struct {
		check core.Check
		await Await
	}
	var (
		out      []core.Result
		inflight []pending
	)
	for _, c := range group {
		if app, ok := c.(core.Applicable); ok && !app.AppliesTo(ev) {
			out = append(out, core.Result{
				Check: c.Name(), Version: c.Version(), Tier: c.Tier(),
				Skipped: true, Err: skipNotApplicable,
			})
			x.observeSkip(c, skipNotApplicable)
			continue
		}
		check := c
		task := func(ctx context.Context) (core.Result, error) {
			return x.runOne(ctx, check, ev)
		}
		name := "check:" + c.Name() + "@" + c.Version()
		spawn := x.Spawn
		if spawn == nil {
			spawn = goroutineSpawner
		}
		inflight = append(inflight, pending{check: c, await: spawn(ctx, name, task)})
	}
	for _, p := range inflight {
		res, err := p.await(ctx)
		if err != nil {
			res = core.Result{
				Check: p.check.Name(), Version: p.check.Version(), Tier: p.check.Tier(),
				Err: err.Error(),
			}
			if x.Metrics != nil {
				x.Metrics.CheckErrors.WithLabelValues(p.check.Name(), p.check.Version()).Inc()
			}
		}
		out = append(out, res)
	}
	return out
}

// runOne runs a single check with its tier's timeout and records its metrics.
// A panicking check is contained: a bad regex in one detector must not take
// down the evaluation of an event.
func (x *Executor) runOne(ctx context.Context, c core.Check, ev core.Event) (res core.Result, err error) {
	res = core.Result{Check: c.Name(), Version: c.Version(), Tier: c.Tier()}
	if d := x.TierTimeout[c.Tier()]; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("check %s panicked: %v", c.Name(), r)
			res.Err = err.Error()
		}
	}()

	start := time.Now()
	verdict, runErr := c.Run(ctx, ev)
	if verdict.Latency == 0 {
		verdict.Latency = time.Since(start)
	}
	res.Verdict = verdict
	if x.Metrics != nil {
		x.Metrics.CheckLatency.WithLabelValues(c.Name(), c.Version(), c.Tier().String()).Observe(verdict.Latency.Seconds())
		if verdict.CostUSD > 0 {
			x.Metrics.CheckCost.WithLabelValues(c.Name(), c.Version()).Add(verdict.CostUSD)
		}
	}
	if runErr != nil {
		res.Err = runErr.Error()
		if x.Metrics != nil {
			x.Metrics.CheckErrors.WithLabelValues(c.Name(), c.Version()).Inc()
		}
		// The error is reported on the result, not returned: one broken check
		// must not fail the whole event, and the policy can still see what the
		// others found.
		return res, nil
	}
	if x.Metrics != nil {
		label := verdict.Label
		if label == "" {
			label = core.LabelOK
		}
		x.Metrics.CheckVerdicts.WithLabelValues(c.Name(), c.Version(), label).Inc()
	}
	return res, nil
}

func (x *Executor) observeSkip(c core.Check, reason string) {
	if x.Metrics != nil {
		x.Metrics.ChecksSkipped.WithLabelValues(c.Name(), reason).Inc()
	}
}

// goroutineSpawner is the non-durable spawner used by the eval harness, dry
// runs, and tests.
func goroutineSpawner(ctx context.Context, _ string, t Task) Await {
	type outcome struct {
		res core.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := t(ctx)
		done <- outcome{res, err}
	}()
	return func(ctx context.Context) (core.Result, error) {
		select {
		case o := <-done:
			return o.res, o.err
		case <-ctx.Done():
			return core.Result{}, ctx.Err()
		}
	}
}

// tierLabel is used in step names so a workflow's history reads clearly.
func tierLabel(t core.Tier) string { return strconv.Itoa(int(t)) + ":" + t.String() }
