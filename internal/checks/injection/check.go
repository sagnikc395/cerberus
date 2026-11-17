package injection

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
)

// DirectCheck reads the prompt the user or agent composed and looks for an
// attempt to overwrite the instructions it was given.
type DirectCheck struct {
	// Threshold is the score at or above which the verdict is labelled. Below
	// it the check still reports evidence with label ok, which is what lets the
	// eval harness sweep the threshold without rerunning the detector.
	Threshold float64
	Ver       string
}

// NewDirectCheck returns the direct prompt-injection check.
func NewDirectCheck() *DirectCheck { return &DirectCheck{Threshold: 0.5, Ver: "1.0.0"} }

func (c *DirectCheck) Name() string    { return "injection_direct" }
func (c *DirectCheck) Version() string { return c.Ver }
func (c *DirectCheck) Tier() core.Tier { return core.TierRegex }

func (c *DirectCheck) AppliesTo(ev core.Event) bool { return ev.Prompt != "" }

// Configure reads {"threshold": 0.6}.
func (c *DirectCheck) Configure(params map[string]any) error {
	t, err := floatParam(params, "threshold", c.Threshold)
	if err != nil {
		return err
	}
	c.Threshold = t
	return nil
}

func (c *DirectCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	hits := Scan(ev.Prompt, false)
	v := verdictFrom(hits, c.Threshold, "injection_direct", core.FieldPrompt, 0)
	v.Latency = time.Since(start)
	return v, nil
}

// IndirectCheck reads the untrusted material that got into the context window
// -- retrieved documents, tool output, fetched pages -- and looks for text
// addressed to the model rather than to the user.
type IndirectCheck struct {
	Threshold float64
	Ver       string
}

// NewIndirectCheck returns the indirect prompt-injection check.
func NewIndirectCheck() *IndirectCheck { return &IndirectCheck{Threshold: 0.45, Ver: "1.0.0"} }

func (c *IndirectCheck) Name() string    { return "injection_indirect" }
func (c *IndirectCheck) Version() string { return c.Ver }
func (c *IndirectCheck) Tier() core.Tier { return core.TierRegex }

func (c *IndirectCheck) AppliesTo(ev core.Event) bool { return len(ev.Untrusted()) > 0 }

func (c *IndirectCheck) Configure(params map[string]any) error {
	t, err := floatParam(params, "threshold", c.Threshold)
	if err != nil {
		return err
	}
	c.Threshold = t
	return nil
}

func (c *IndirectCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	best := core.Verdict{Label: core.LabelOK}
	for _, i := range ev.Untrusted() {
		hits := Scan(ev.Context[i].Content, true)
		v := verdictFrom(hits, c.Threshold, "injection_indirect", core.FieldContext, i)
		if v.Score > best.Score {
			best = v
		} else if v.Score == best.Score {
			best.Evidence = append(best.Evidence, v.Evidence...)
		}
	}
	best.Latency = time.Since(start)
	return best, nil
}

// verdictFrom turns hits into a verdict. Evidence is kept even when the score
// lands below the threshold: the span is what a reviewer reads, and the eval
// harness needs the score of the events that did not fire.
func verdictFrom(hits []Hit, threshold float64, label string, field core.Field, index int) core.Verdict {
	if len(hits) == 0 {
		return core.Verdict{Label: core.LabelOK}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Weight > hits[j].Weight })
	spans := make([]core.Span, 0, len(hits))
	names := make([]string, 0, len(hits))
	for _, h := range hits {
		spans = append(spans, core.Span{
			Field: field,
			Index: index,
			Start: h.Start,
			End:   h.End,
			Text:  h.Text,
			Note:  h.Signature,
		})
		names = append(names, h.Signature)
	}
	v := core.Verdict{Score: Score(hits), Evidence: spans, Label: core.LabelOK}
	if v.Score >= threshold {
		v.Label = label
	}
	if len(v.Evidence) > 0 {
		v.Evidence[0].Note = strings.Join(names, "+")
	}
	return v
}

func floatParam(params map[string]any, name string, def float64) (float64, error) {
	raw, ok := params[name]
	if !ok {
		return def, nil
	}
	switch n := raw.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	}
	return 0, fmt.Errorf("injection: %s must be a number, got %T", name, raw)
}
