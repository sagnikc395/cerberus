package eval

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/engine"
)

// TestRepositoryDatasetsMeetTheContract is the gate the CI workflow runs: the
// checks in this repository must stay within eval/thresholds.yaml and at or
// above eval/baseline.json.
func TestRepositoryDatasetsMeetTheContract(t *testing.T) {
	root := repoRoot(t)
	cases, err := LoadDir(filepath.Join(root, "eval", "datasets"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), engine.DefaultRegistry(), cases)
	if err != nil {
		t.Fatal(err)
	}
	thresholds, err := LoadThresholds(filepath.Join(root, "eval", "thresholds.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(filepath.Join(root, "eval", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range append(thresholds.Enforce(report), thresholds.CompareBaseline(baseline, report)...) {
		t.Errorf("%s", f)
	}
}

func TestEnforceReportsEveryKindOfShortfall(t *testing.T) {
	report := Report{Checks: []Metrics{{
		Check: "pii_leak", Version: "1.0.0", Dataset: "pii",
		TruePositives: 1, FalsePositives: 4, FalseNegatives: 3, TrueNegatives: 6,
	}}}
	for i := range report.Checks {
		report.Checks[i].finalize(nil)
	}
	th := &Thresholds{Tolerance: 0.02, Checks: map[string]Threshold{
		"pii_leak": {MinPrecision: 0.9, MinRecall: 0.9, MaxFPR: 0.05, MinCases: 2},
		"gone":     {MinPrecision: 0.9},
	}}
	failures := th.Enforce(report)
	seen := map[string]bool{}
	for _, f := range failures {
		seen[f.Check+":"+f.Metric] = true
	}
	for _, want := range []string{"pii_leak:precision", "pii_leak:recall", "pii_leak:fpr", "gone:missing"} {
		if !seen[want] {
			t.Errorf("missing failure %s in %v", want, failures)
		}
	}
}

func TestCompareBaselineCatchesARegressionAndToleratesNoise(t *testing.T) {
	baseline := &Baseline{Checks: map[string]Metrics{
		"injection_direct@1.0.0": {Check: "injection_direct", Version: "1.0.0", Precision: 0.90, Recall: 0.80, FPR: 0.02},
	}}
	th := &Thresholds{Tolerance: 0.02}

	// Metrics are recomputed from the counts, so the cases are expressed the
	// way a real run produces them.
	noise := Report{Checks: []Metrics{{Check: "injection_direct", Version: "1.0.0",
		TruePositives: 89, FalsePositives: 11, FalseNegatives: 24, TrueNegatives: 356}}}
	if got := th.CompareBaseline(baseline, noise); len(got) != 0 {
		t.Errorf("noise inside the tolerance failed the gate: %v", got)
	}
	regression := Report{Checks: []Metrics{{Check: "injection_direct", Version: "1.0.0",
		TruePositives: 70, FalsePositives: 30, FalseNegatives: 70, TrueNegatives: 70}}}
	if got := th.CompareBaseline(baseline, regression); len(got) != 3 {
		t.Errorf("got %d failures, want 3: %v", len(got), got)
	}
}

func TestCasesCarryTheirOwnCheckConfiguration(t *testing.T) {
	reg := engine.DefaultRegistry()
	cases := []Case{{
		ID: "c1", Dataset: "d", Expect: []string{"tool_allowlist"},
		Event: core.Event{ID: "c1", AgentID: "eval", Kind: core.KindToolCall,
			ToolCall: &core.ToolCall{Name: "delete_customer", Args: map[string]any{"id": "1"}}},
		Config: map[string]map[string]any{"tool_allowlist": {"allow": []any{"lookup_order"}}},
	}}
	report, err := Run(context.Background(), reg, cases)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range report.Checks {
		if m.Check != "tool_allowlist" {
			continue
		}
		if m.TruePositives != 1 {
			t.Errorf("tool_allowlist did not fire on an undeclared tool: %+v", m)
		}
		return
	}
	t.Error("tool_allowlist produced no metrics")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repository root")
	return ""
}
