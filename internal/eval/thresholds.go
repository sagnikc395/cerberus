package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// Threshold is the accuracy one check must hold. A check with no entry is
// reported but not enforced, which is how an experimental detector ships
// without being able to break the build.
type Threshold struct {
	MinPrecision float64 `yaml:"min_precision" json:"min_precision"`
	MinRecall    float64 `yaml:"min_recall" json:"min_recall"`
	MaxFPR       float64 `yaml:"max_fpr" json:"max_fpr"`
	MinCases     int     `yaml:"min_cases" json:"min_cases"`
}

// Thresholds is the enforced contract, loaded from eval/thresholds.yaml.
type Thresholds struct {
	// Tolerance is how far a metric may fall below the recorded baseline
	// before the run fails. It absorbs the noise of adding cases, not a real
	// regression.
	Tolerance float64              `yaml:"tolerance" json:"tolerance"`
	Checks    map[string]Threshold `yaml:"checks" json:"checks"`
}

// LoadThresholds reads the contract.
func LoadThresholds(path string) (*Thresholds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Thresholds
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if t.Tolerance == 0 {
		t.Tolerance = 0.02
	}
	return &t, nil
}

// Failure is one violated expectation.
type Failure struct {
	Check   string  `json:"check"`
	Metric  string  `json:"metric"`
	Want    float64 `json:"want"`
	Got     float64 `json:"got"`
	Against string  `json:"against"` // "threshold" or "baseline"
}

func (f Failure) String() string {
	switch f.Metric {
	case "cases":
		return fmt.Sprintf("%s: %s %.0f, want at least %.0f (%s)", f.Check, f.Metric, f.Got, f.Want, f.Against)
	case "fpr":
		return fmt.Sprintf("%s: fpr %.3f, want at most %.3f (%s)", f.Check, f.Got, f.Want, f.Against)
	default:
		return fmt.Sprintf("%s: %s %.3f, want at least %.3f (%s)", f.Check, f.Metric, f.Got, f.Want, f.Against)
	}
}

// Enforce checks a report against the thresholds. An unknown check name in the
// contract is itself a failure: a renamed detector must not silently stop
// being enforced.
func (t *Thresholds) Enforce(r Report) []Failure {
	overall := map[string]Metrics{}
	for _, m := range r.Overall() {
		overall[m.Check] = m
	}
	var failures []Failure
	names := make([]string, 0, len(t.Checks))
	for name := range t.Checks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		want := t.Checks[name]
		got, ok := overall[name]
		if !ok {
			failures = append(failures, Failure{
				Check: name, Metric: "missing", Against: "threshold",
			})
			continue
		}
		cases := got.TruePositives + got.FalseNegatives
		if want.MinCases > 0 && cases < want.MinCases {
			failures = append(failures, Failure{Check: name, Metric: "cases", Want: float64(want.MinCases), Got: float64(cases), Against: "threshold"})
		}
		if want.MinPrecision > 0 && got.Precision < want.MinPrecision {
			failures = append(failures, Failure{Check: name, Metric: "precision", Want: want.MinPrecision, Got: got.Precision, Against: "threshold"})
		}
		if want.MinRecall > 0 && got.Recall < want.MinRecall {
			failures = append(failures, Failure{Check: name, Metric: "recall", Want: want.MinRecall, Got: got.Recall, Against: "threshold"})
		}
		if want.MaxFPR > 0 && got.FPR > want.MaxFPR {
			failures = append(failures, Failure{Check: name, Metric: "fpr", Want: want.MaxFPR, Got: got.FPR, Against: "threshold"})
		}
	}
	return failures
}

// Baseline is a recorded report a later run is compared against.
type Baseline struct {
	Checks map[string]Metrics `json:"checks"`
}

// LoadBaseline reads a recorded baseline. A missing file is not an error: the
// first run on a new check has nothing to compare against.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Baseline{Checks: map[string]Metrics{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if b.Checks == nil {
		b.Checks = map[string]Metrics{}
	}
	return &b, nil
}

// SaveBaseline records a report as the new baseline.
func SaveBaseline(path string, r Report) error {
	b := Baseline{Checks: map[string]Metrics{}}
	for _, m := range r.Overall() {
		b.Checks[m.Check+"@"+m.Version] = m
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// CompareBaseline reports every metric that fell further than the tolerance
// below what the same check version scored before. This is the check that
// makes "a PR that lowers a detector's metrics fails CI" true.
func (t *Thresholds) CompareBaseline(b *Baseline, r Report) []Failure {
	var failures []Failure
	for _, got := range r.Overall() {
		prev, ok := b.Checks[got.Check+"@"+got.Version]
		if !ok {
			continue // a new version is measured, not compared
		}
		if got.Precision < prev.Precision-t.Tolerance {
			failures = append(failures, Failure{Check: got.Check, Metric: "precision", Want: prev.Precision, Got: got.Precision, Against: "baseline"})
		}
		if got.Recall < prev.Recall-t.Tolerance {
			failures = append(failures, Failure{Check: got.Check, Metric: "recall", Want: prev.Recall, Got: got.Recall, Against: "baseline"})
		}
		if got.FPR > prev.FPR+t.Tolerance {
			failures = append(failures, Failure{Check: got.Check, Metric: "fpr", Want: prev.FPR, Got: got.FPR, Against: "baseline"})
		}
	}
	sort.Slice(failures, func(i, j int) bool {
		if failures[i].Check != failures[j].Check {
			return failures[i].Check < failures[j].Check
		}
		return failures[i].Metric < failures[j].Metric
	})
	return failures
}
