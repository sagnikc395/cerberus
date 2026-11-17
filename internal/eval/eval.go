// Package eval measures the checks. A check's verdict is only as good as the
// labeled set it was measured on, so every detector reports precision, recall
// and false-positive rate per version, and CI fails a change that lowers them.
package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/engine"
)

// Case is one labeled example. Expect lists the checks that should fire on
// it; every other check is expected to stay clean, which is what makes a
// benign case a false-positive test for all of them at once.
type Case struct {
	ID      string     `json:"id"`
	Dataset string     `json:"dataset,omitempty"`
	Note    string     `json:"note,omitempty"`
	Expect  []string   `json:"expect"`
	Event   core.Event `json:"event"`
	// Source records where the example came from: a reviewer decision, a
	// published attack set, or a hand-written regression.
	Source string `json:"source,omitempty"`
	// Config configures the checks for this case, keyed by check name. A
	// detector whose verdict depends on an agent's allowlist or bounds cannot
	// be measured without one, so the case carries the configuration it is
	// labeled against.
	Config map[string]map[string]any `json:"config,omitempty"`
}

// expects reports whether a check is supposed to fire on this case.
func (c Case) expects(check string) bool {
	for _, name := range c.Expect {
		if name == check {
			return true
		}
	}
	return false
}

// LoadJSONL reads one dataset file.
func LoadJSONL(path string) ([]Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	var out []Case
	dec := json.NewDecoder(f)
	for line := 1; ; line++ {
		var c Case
		err := dec.Decode(&c)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		if c.ID == "" {
			return nil, fmt.Errorf("%s line %d: case needs an id", path, line)
		}
		if c.Dataset == "" {
			c.Dataset = name
		}
		if c.Event.ID == "" {
			c.Event.ID = c.ID
		}
		if c.Event.AgentID == "" {
			c.Event.AgentID = "eval"
		}
		if c.Event.CreatedAt.IsZero() {
			c.Event.CreatedAt = time.Unix(0, 0).UTC()
		}
		out = append(out, c)
	}
	return out, nil
}

// LoadDir reads every .jsonl dataset in a directory.
func LoadDir(dir string) ([]Case, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Case
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".jsonl" {
			continue
		}
		cases, err := LoadJSONL(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, cases...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("eval: no cases in %s", dir)
	}
	return out, nil
}

// Metrics is one check version's accuracy on one dataset.
type Metrics struct {
	Check   string `json:"check"`
	Version string `json:"check_version"`
	Dataset string `json:"dataset"`

	TruePositives  int `json:"tp"`
	FalsePositives int `json:"fp"`
	FalseNegatives int `json:"fn"`
	TrueNegatives  int `json:"tn"`
	Errors         int `json:"errors"`
	Skipped        int `json:"skipped"`

	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	FPR       float64 `json:"fpr"`
	F1        float64 `json:"f1"`

	LatencyP50 time.Duration `json:"latency_p50"`
	LatencyP95 time.Duration `json:"latency_p95"`
	CostUSD    float64       `json:"cost_usd"`

	// Misses and FalseAlarms name the cases that went wrong, because a number
	// without the failing example is not actionable.
	Misses      []string `json:"misses,omitempty"`
	FalseAlarms []string `json:"false_alarms,omitempty"`
}

// Report is a full run.
type Report struct {
	RanAt    time.Time `json:"ran_at"`
	Cases    int       `json:"cases"`
	Checks   []Metrics `json:"checks"`
	Datasets []string  `json:"datasets"`
}

const maxExamples = 10

// Run evaluates every check in the registry against the cases. Checks run
// unconfigured by policy: the eval measures the detector, not one agent's
// thresholds.
func Run(ctx context.Context, reg *core.Registry, cases []Case) (Report, error) {
	plan := engine.Plan{Agent: "eval"}
	for _, c := range reg.All() {
		plan.Checks = append(plan.Checks, core.Clone(c))
	}
	// Every tier runs on every case: a tier skipped for cost in production is
	// still measured here, or its numbers would be unknown.
	exec := engine.NewExecutor(nil)
	exec.Escalation = engine.Escalation{Always: true}

	type key struct {
		check, version, dataset string
	}
	agg := map[key]*Metrics{}
	latencies := map[key][]time.Duration{}
	datasets := map[string]bool{}

	for _, tc := range cases {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		datasets[tc.Dataset] = true
		casePlan, err := configure(plan, tc.Config)
		if err != nil {
			return Report{}, fmt.Errorf("case %s: %w", tc.ID, err)
		}
		results := exec.Run(ctx, casePlan, tc.Event)
		for _, res := range results {
			k := key{res.Check, res.Version, tc.Dataset}
			m := agg[k]
			if m == nil {
				m = &Metrics{Check: res.Check, Version: res.Version, Dataset: tc.Dataset}
				agg[k] = m
			}
			expected := tc.expects(res.Check)
			switch {
			case res.Skipped:
				m.Skipped++
				// A check that cannot apply to a case is not evidence either
				// way, unless the case says it should have fired.
				if expected {
					m.FalseNegatives++
					m.Misses = appendCapped(m.Misses, tc.ID)
				}
				continue
			case res.Err != "":
				m.Errors++
				if expected {
					m.FalseNegatives++
					m.Misses = appendCapped(m.Misses, tc.ID)
				}
				continue
			}
			latencies[k] = append(latencies[k], res.Verdict.Latency)
			m.CostUSD += res.Verdict.CostUSD
			flagged := res.Verdict.Flagged()
			switch {
			case flagged && expected:
				m.TruePositives++
			case flagged && !expected:
				m.FalsePositives++
				m.FalseAlarms = appendCapped(m.FalseAlarms, tc.ID)
			case !flagged && expected:
				m.FalseNegatives++
				m.Misses = appendCapped(m.Misses, tc.ID)
			default:
				m.TrueNegatives++
			}
		}
	}

	report := Report{RanAt: time.Now().UTC(), Cases: len(cases)}
	for k, m := range agg {
		m.finalize(latencies[k])
		report.Checks = append(report.Checks, *m)
	}
	sort.Slice(report.Checks, func(i, j int) bool {
		a, b := report.Checks[i], report.Checks[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Dataset < b.Dataset
	})
	for d := range datasets {
		report.Datasets = append(report.Datasets, d)
	}
	sort.Strings(report.Datasets)
	return report, nil
}

// configure returns a plan with this case's check configuration applied. The
// shared plan is left untouched, so one case cannot change what the next one
// measures.
func configure(plan engine.Plan, config map[string]map[string]any) (engine.Plan, error) {
	if len(config) == 0 {
		return plan, nil
	}
	out := engine.Plan{Agent: plan.Agent, Checks: make([]core.Check, 0, len(plan.Checks))}
	for _, c := range plan.Checks {
		params, ok := config[c.Name()]
		if !ok {
			out.Checks = append(out.Checks, c)
			continue
		}
		clone := core.Clone(c)
		cfg, ok := clone.(core.Configurable)
		if !ok {
			return engine.Plan{}, fmt.Errorf("check %s takes no params", c.Name())
		}
		if err := cfg.Configure(params); err != nil {
			return engine.Plan{}, fmt.Errorf("configure %s: %w", c.Name(), err)
		}
		out.Checks = append(out.Checks, clone)
	}
	return out, nil
}

func (m *Metrics) finalize(latencies []time.Duration) {
	if n := m.TruePositives + m.FalsePositives; n > 0 {
		m.Precision = float64(m.TruePositives) / float64(n)
	}
	if n := m.TruePositives + m.FalseNegatives; n > 0 {
		m.Recall = float64(m.TruePositives) / float64(n)
	}
	if n := m.FalsePositives + m.TrueNegatives; n > 0 {
		m.FPR = float64(m.FalsePositives) / float64(n)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	if len(latencies) == 0 {
		return
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	m.LatencyP50 = percentile(latencies, 0.50)
	m.LatencyP95 = percentile(latencies, 0.95)
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return sorted[i]
}

func appendCapped(list []string, id string) []string {
	if len(list) >= maxExamples {
		return list
	}
	return append(list, id)
}

// Overall collapses a check's per-dataset rows into one, for the summary line
// and for threshold enforcement.
func (r Report) Overall() []Metrics {
	type key struct{ check, version string }
	agg := map[key]*Metrics{}
	var order []key
	for _, m := range r.Checks {
		k := key{m.Check, m.Version}
		acc := agg[k]
		if acc == nil {
			acc = &Metrics{Check: m.Check, Version: m.Version, Dataset: "all"}
			agg[k] = acc
			order = append(order, k)
		}
		acc.TruePositives += m.TruePositives
		acc.FalsePositives += m.FalsePositives
		acc.FalseNegatives += m.FalseNegatives
		acc.TrueNegatives += m.TrueNegatives
		acc.Errors += m.Errors
		acc.Skipped += m.Skipped
		acc.CostUSD += m.CostUSD
		if m.LatencyP95 > acc.LatencyP95 {
			acc.LatencyP95 = m.LatencyP95
		}
		acc.Misses = appendAllCapped(acc.Misses, m.Misses)
		acc.FalseAlarms = appendAllCapped(acc.FalseAlarms, m.FalseAlarms)
	}
	out := make([]Metrics, 0, len(order))
	for _, k := range order {
		m := agg[k]
		m.finalize(nil)
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Check != out[j].Check {
			return out[i].Check < out[j].Check
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func appendAllCapped(dst, src []string) []string {
	for _, s := range src {
		dst = appendCapped(dst, s)
	}
	return dst
}
