package pii

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
)

// Mask replaces a detected value with its shape and a short tail, so evidence
// is reviewable without storing the data that triggered the check.
func Mask(t Type, value string) string {
	d := digits(value)
	switch t {
	case CreditCard:
		if len(d) >= 4 {
			return "card ****" + d[len(d)-4:]
		}
	case SSN:
		return "ssn ***-**-" + tail(d, 4)
	case IBAN:
		return "iban " + strings.ToUpper(value[:min(4, len(value))]) + "***"
	case Email:
		if at := strings.IndexByte(value, '@'); at > 0 {
			return value[:1] + "***@" + value[at+1:]
		}
	case Phone:
		return "phone ***-" + tail(d, 4)
	}
	return string(t) + " <redacted>"
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// scan runs the detectors over a set of fields and turns matches into spans.
func scan(ev core.Event, fields []core.Field, types []Type) ([]core.Span, map[Type]int, float64) {
	spans := []core.Span{}
	counts := map[Type]int{}
	var top float64
	add := func(f core.Field, index int, text string) {
		for _, m := range ScanTypes(text, types) {
			counts[m.Type]++
			if s := m.Severity(); s > top {
				top = s
			}
			spans = append(spans, core.Span{
				Field: f,
				Index: index,
				Start: m.Start,
				End:   m.End,
				Text:  Mask(m.Type, m.Value),
				Note:  string(m.Type),
			})
		}
	}
	for _, f := range fields {
		switch f {
		case core.FieldContext:
			for i := range ev.Context {
				add(f, i, ev.Context[i].Content)
			}
		default:
			add(f, 0, ev.Text(f, 0))
		}
	}
	return spans, counts, top
}

// score turns the detections into 0..1: the highest-severity type sets the
// floor, additional distinct hits push it up, and it saturates at 0.99 so a
// policy can still distinguish a reviewer-confirmed label from a detector's.
func score(counts map[Type]int, top float64) float64 {
	if len(counts) == 0 {
		return 0
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	s := top + 0.05*float64(total-1) + 0.05*float64(len(counts)-1)
	if s > 0.99 {
		s = 0.99
	}
	return s
}

func summarize(counts map[Type]int) string {
	kinds := make([]string, 0, len(counts))
	for t := range counts {
		kinds = append(kinds, string(t))
	}
	sort.Strings(kinds)
	return strings.Join(kinds, ",")
}

// PromptCheck finds personal data on the way in: the prompt the agent is about
// to send, plus the untrusted context stuffed into it.
type PromptCheck struct {
	// Types restricts detection; empty means every type.
	Types []Type
	// Ver is the detector version reported in verdicts and eval reports.
	Ver string
}

// NewPromptCheck returns the input-side PII check.
func NewPromptCheck() *PromptCheck { return &PromptCheck{Ver: "1.0.0"} }

func (c *PromptCheck) Name() string    { return "pii_prompt" }
func (c *PromptCheck) Version() string { return c.Ver }
func (c *PromptCheck) Tier() core.Tier { return core.TierRegex }

// AppliesTo skips events with no inbound text.
func (c *PromptCheck) AppliesTo(ev core.Event) bool {
	return ev.Prompt != "" || len(ev.Context) > 0
}

// Configure reads {"types": ["ssn","credit_card"]} from a policy rule.
func (c *PromptCheck) Configure(params map[string]any) error {
	types, err := parseTypes(params)
	if err != nil {
		return err
	}
	c.Types = types
	return nil
}

func (c *PromptCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	spans, counts, top := scan(ev, []core.Field{core.FieldPrompt, core.FieldContext}, c.Types)
	v := core.Verdict{Label: core.LabelOK, Latency: time.Since(start)}
	if len(counts) > 0 {
		v.Label = "pii_prompt"
		v.Score = score(counts, top)
		v.Evidence = spans
		v.Latency = time.Since(start)
		if len(spans) > 0 {
			spans[0].Note = summarize(counts)
		}
	}
	return v, nil
}

// LeakCheck finds personal data on the way out: the completion the agent is
// about to return, and the arguments of the tool call it wants to make.
type LeakCheck struct {
	Types []Type
	Ver   string
}

// NewLeakCheck returns the output-side PII check.
func NewLeakCheck() *LeakCheck { return &LeakCheck{Ver: "1.0.0"} }

func (c *LeakCheck) Name() string    { return "pii_leak" }
func (c *LeakCheck) Version() string { return c.Ver }
func (c *LeakCheck) Tier() core.Tier { return core.TierRegex }

func (c *LeakCheck) AppliesTo(ev core.Event) bool {
	return ev.Completion != "" || ev.ToolCall != nil
}

func (c *LeakCheck) Configure(params map[string]any) error {
	types, err := parseTypes(params)
	if err != nil {
		return err
	}
	c.Types = types
	return nil
}

func (c *LeakCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	spans, counts, top := scan(ev, []core.Field{core.FieldCompletion, core.FieldToolArgs}, c.Types)
	v := core.Verdict{Label: core.LabelOK, Latency: time.Since(start)}
	if len(counts) == 0 {
		return v, nil
	}
	// A leak is worse than an inbound mention: the data is leaving the system,
	// and in the outbound direction there is no user who typed it on purpose.
	v.Label = "pii_leak"
	v.Score = score(counts, top)
	if v.Score < 0.5 {
		v.Score = 0.5
	}
	v.Evidence = spans
	v.Latency = time.Since(start)
	return v, nil
}

func parseTypes(params map[string]any) ([]Type, error) {
	raw, ok := params["types"]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("pii: types must be a list")
	}
	out := make([]Type, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("pii: type %v is not a string", item)
		}
		out = append(out, Type(s))
	}
	return out, nil
}
