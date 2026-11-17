// Package metrics is the platform's own health: what it received, how long
// each check took, what it cost, what the policy did about it, and how deep
// the review queue is. Everything the dashboard draws comes from here.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds the collectors. One instance is registered per process; tests
// build their own against a fresh registry.
type Metrics struct {
	EventsReceived  *prometheus.CounterVec
	EventsEvaluated *prometheus.CounterVec
	IngestErrors    *prometheus.CounterVec

	CheckLatency  *prometheus.HistogramVec
	CheckVerdicts *prometheus.CounterVec
	CheckErrors   *prometheus.CounterVec
	CheckCost     *prometheus.CounterVec
	ChecksSkipped *prometheus.CounterVec
	TierRuns      *prometheus.CounterVec

	PolicyActions *prometheus.CounterVec
	Violations    *prometheus.CounterVec
	Redactions    prometheus.Counter

	EvaluationLatency *prometheus.HistogramVec
	QueueLag          prometheus.Gauge
	QueueDepth        *prometheus.GaugeVec
	ReviewDepth       *prometheus.GaugeVec
	ReviewerPrecision *prometheus.GaugeVec
	ReviewDecisions   *prometheus.CounterVec
}

// New registers the collectors on reg.
func New(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		EventsReceived: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_events_received_total",
			Help: "Events accepted by the ingest API, by agent and kind.",
		}, []string{"agent", "kind"}),
		EventsEvaluated: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_events_evaluated_total",
			Help: "Events that completed evaluation, by agent and final action.",
		}, []string{"agent", "action"}),
		IngestErrors: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_ingest_errors_total",
			Help: "Events rejected at ingest, by reason.",
		}, []string{"reason"}),

		CheckLatency: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cerberus_check_latency_seconds",
			Help:    "Wall time of one check run.",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
		}, []string{"check", "version", "tier"}),
		CheckVerdicts: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_check_verdicts_total",
			Help: "Verdicts returned, by check version and label.",
		}, []string{"check", "version", "label"}),
		CheckErrors: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_check_errors_total",
			Help: "Checks that failed or timed out.",
		}, []string{"check", "version"}),
		CheckCost: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_check_cost_usd_total",
			Help: "Metered spend attributed to a check.",
		}, []string{"check", "version"}),
		ChecksSkipped: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_checks_skipped_total",
			Help: "Checks not run, by reason: not applicable, disabled, or tier not escalated.",
		}, []string{"check", "reason"}),
		TierRuns: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_tier_runs_total",
			Help: "How often each execution tier ran, which is what tiering is meant to keep low.",
		}, []string{"tier"}),

		PolicyActions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_policy_actions_total",
			Help: "Actions a policy decided, by agent, action and severity.",
		}, []string{"agent", "policy_version", "action", "severity"}),
		Violations: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_violations_total",
			Help: "Violations recorded, by agent, check and action.",
		}, []string{"agent", "check", "action"}),
		Redactions: f.NewCounter(prometheus.CounterOpts{
			Name: "cerberus_redactions_total",
			Help: "Values masked before persistence.",
		}),

		EvaluationLatency: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cerberus_evaluation_seconds",
			Help:    "End-to-end time from the start of a workflow to a stored decision.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
		}, []string{"agent"}),
		QueueLag: f.NewGauge(prometheus.GaugeOpts{
			Name: "cerberus_broker_lag_seconds",
			Help: "Age of the oldest event the engine has not finished evaluating.",
		}),
		QueueDepth: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cerberus_broker_depth",
			Help: "Events waiting in the broker.",
		}, []string{"subject"}),
		ReviewDepth: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cerberus_review_queue_depth",
			Help: "Pending review items, by agent.",
		}, []string{"agent"}),
		ReviewerPrecision: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cerberus_check_reviewer_precision",
			Help: "Share of a check version's flags that reviewers confirmed.",
		}, []string{"check", "version"}),
		ReviewDecisions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_review_decisions_total",
			Help: "Reviewer decisions, by agent and state.",
		}, []string{"agent", "state"}),
	}
}

// Default registers on the default registry, which is what /metrics serves.
func Default() *Metrics { return New(prometheus.DefaultRegisterer) }
