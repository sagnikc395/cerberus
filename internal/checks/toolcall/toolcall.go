// Package toolcall holds the agent-behaviour guardrails: which tools an agent
// may call, whether the arguments are inside their declared bounds, and
// whether a call was put there by injected content rather than by the user.
package toolcall

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagnikc395/cerberus/internal/checks/injection"
	"github.com/sagnikc395/cerberus/internal/core"
)

// AllowlistCheck flags any tool the agent is not declared to use. An agent
// with no allowlist configured is reported as unconfigured rather than clean,
// because silence here would look identical to a passing check.
type AllowlistCheck struct {
	// Allow is the set of permitted tool names. A trailing "*" allows a prefix.
	Allow []string
	Ver   string
}

// NewAllowlistCheck returns the tool-allowlist check.
func NewAllowlistCheck() *AllowlistCheck { return &AllowlistCheck{Ver: "1.0.0"} }

func (c *AllowlistCheck) Name() string                 { return "tool_allowlist" }
func (c *AllowlistCheck) Version() string              { return c.Ver }
func (c *AllowlistCheck) Tier() core.Tier              { return core.TierRegex }
func (c *AllowlistCheck) AppliesTo(ev core.Event) bool { return ev.ToolCall != nil }

// Configure reads {"allow": ["search", "lookup_*"]}.
func (c *AllowlistCheck) Configure(params map[string]any) error {
	list, err := stringList(params, "allow")
	if err != nil {
		return err
	}
	c.Allow = list
	return nil
}

func (c *AllowlistCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	v := core.Verdict{Label: core.LabelOK}
	defer func() { v.Latency = time.Since(start) }()
	if ev.ToolCall == nil {
		return v, nil
	}
	if len(c.Allow) == 0 {
		v.Label = "tool_allowlist_unconfigured"
		v.Score = 0.3
		v.Evidence = []core.Span{{Field: core.FieldToolArgs, Text: ev.ToolCall.Name, Note: "no allowlist configured for this agent"}}
		return v, nil
	}
	if allowed(c.Allow, ev.ToolCall.Name) {
		return v, nil
	}
	v.Label = "tool_not_allowed"
	v.Score = 0.95
	v.Evidence = []core.Span{{
		Field: core.FieldToolArgs,
		Text:  ev.ToolCall.Name,
		Note:  "allowed: " + strings.Join(c.Allow, ", "),
	}}
	return v, nil
}

func allowed(list []string, name string) bool {
	for _, a := range list {
		if a == name {
			return true
		}
		if strings.HasSuffix(a, "*") && strings.HasPrefix(name, strings.TrimSuffix(a, "*")) {
			return true
		}
	}
	return false
}

// Bound is the declared range of one argument.
type Bound struct {
	Max       *float64 `json:"max,omitempty" yaml:"max"`
	Min       *float64 `json:"min,omitempty" yaml:"min"`
	MaxLen    *int     `json:"max_len,omitempty" yaml:"max_len"`
	OneOf     []string `json:"one_of,omitempty" yaml:"one_of"`
	MatchesRe string   `json:"matches,omitempty" yaml:"matches"`
}

// ToolSpec is one tool's declared argument contract.
type ToolSpec struct {
	Required []string         `json:"required,omitempty" yaml:"required"`
	Args     map[string]Bound `json:"args,omitempty" yaml:"args"`
}

// BoundsCheck compares a tool call's arguments against the tool's declared
// contract: required arguments present, numbers in range, strings within
// length, enums inside their set.
type BoundsCheck struct {
	Tools map[string]ToolSpec
	Ver   string
}

// NewBoundsCheck returns the argument-bounds check.
func NewBoundsCheck() *BoundsCheck {
	return &BoundsCheck{Tools: map[string]ToolSpec{}, Ver: "1.0.0"}
}

func (c *BoundsCheck) Name() string                 { return "tool_call_bounds" }
func (c *BoundsCheck) Version() string              { return c.Ver }
func (c *BoundsCheck) Tier() core.Tier              { return core.TierRegex }
func (c *BoundsCheck) AppliesTo(ev core.Event) bool { return ev.ToolCall != nil }

// Configure reads the tools block of a policy rule:
//
//	params:
//	  tools:
//	    issue_refund:
//	      required: [order_id]
//	      args: { amount: { max: 500 } }
func (c *BoundsCheck) Configure(params map[string]any) error {
	raw, ok := params["tools"]
	if !ok {
		return nil
	}
	tools, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("toolcall: tools must be a mapping")
	}
	out := map[string]ToolSpec{}
	for name, spec := range tools {
		m, ok := spec.(map[string]any)
		if !ok {
			return fmt.Errorf("toolcall: spec for %s must be a mapping", name)
		}
		var ts ToolSpec
		if req, ok := m["required"]; ok {
			list, err := stringList(map[string]any{"required": req}, "required")
			if err != nil {
				return err
			}
			ts.Required = list
		}
		if args, ok := m["args"]; ok {
			am, ok := args.(map[string]any)
			if !ok {
				return fmt.Errorf("toolcall: args for %s must be a mapping", name)
			}
			ts.Args = map[string]Bound{}
			for arg, b := range am {
				bm, ok := b.(map[string]any)
				if !ok {
					return fmt.Errorf("toolcall: bound for %s.%s must be a mapping", name, arg)
				}
				var bound Bound
				if v, ok := numberOf(bm["max"]); ok {
					bound.Max = &v
				}
				if v, ok := numberOf(bm["min"]); ok {
					bound.Min = &v
				}
				if v, ok := numberOf(bm["max_len"]); ok {
					n := int(v)
					bound.MaxLen = &n
				}
				if v, ok := bm["one_of"]; ok {
					list, err := stringList(map[string]any{"one_of": v}, "one_of")
					if err != nil {
						return err
					}
					bound.OneOf = list
				}
				if v, ok := bm["matches"].(string); ok {
					bound.MatchesRe = v
				}
				ts.Args[arg] = bound
			}
		}
		out[name] = ts
	}
	c.Tools = out
	return nil
}

func (c *BoundsCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	v := core.Verdict{Label: core.LabelOK}
	defer func() { v.Latency = time.Since(start) }()
	if ev.ToolCall == nil {
		return v, nil
	}
	spec, ok := c.Tools[ev.ToolCall.Name]
	if !ok {
		return v, nil
	}
	args := ev.ToolCall.Args
	rendered := core.EncodeArgs(args)
	var problems []string
	for _, req := range spec.Required {
		if _, present := args[req]; !present {
			problems = append(problems, "missing required argument "+req)
		}
	}
	names := make([]string, 0, len(spec.Args))
	for name := range spec.Args {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		bound := spec.Args[name]
		value, present := args[name]
		if !present {
			continue
		}
		problems = append(problems, violations(name, bound, value)...)
	}
	if len(problems) == 0 {
		return v, nil
	}
	v.Label = "tool_call_bounds"
	v.Score = 0.9
	v.Evidence = []core.Span{{
		Field: core.FieldToolArgs,
		Start: 0,
		End:   len(rendered),
		Text:  clip(rendered, 300),
		Note:  strings.Join(problems, "; "),
	}}
	return v, nil
}

func violations(name string, b Bound, value any) []string {
	var out []string
	if n, ok := numberOf(value); ok {
		if b.Max != nil && n > *b.Max {
			out = append(out, fmt.Sprintf("%s=%s exceeds max %s", name, trimFloat(n), trimFloat(*b.Max)))
		}
		if b.Min != nil && n < *b.Min {
			out = append(out, fmt.Sprintf("%s=%s below min %s", name, trimFloat(n), trimFloat(*b.Min)))
		}
	}
	s, isString := value.(string)
	if isString {
		if b.MaxLen != nil && len(s) > *b.MaxLen {
			out = append(out, fmt.Sprintf("%s is %d chars, max %d", name, len(s), *b.MaxLen))
		}
		if len(b.OneOf) > 0 && !allowed(b.OneOf, s) {
			out = append(out, fmt.Sprintf("%s=%q not in {%s}", name, clip(s, 40), strings.Join(b.OneOf, ",")))
		}
	}
	return out
}

func trimFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// InjectedCallCheck is the correlation that matters most in practice: an agent
// making a tool call while untrusted content in its context is telling it to.
// It re-runs the indirect-injection signatures itself rather than reading
// another check's verdict, so it stays a pure function of the event and can be
// replayed and scored on its own.
type InjectedCallCheck struct {
	// Threshold is the indirect-injection score the surrounding content must
	// reach before a tool call is attributed to it.
	Threshold float64
	Ver       string
}

// NewInjectedCallCheck returns the injection-triggered tool-call check.
func NewInjectedCallCheck() *InjectedCallCheck {
	return &InjectedCallCheck{Threshold: 0.45, Ver: "1.0.0"}
}

func (c *InjectedCallCheck) Name() string    { return "tool_call_from_injection" }
func (c *InjectedCallCheck) Version() string { return c.Ver }
func (c *InjectedCallCheck) Tier() core.Tier { return core.TierRegex }

func (c *InjectedCallCheck) AppliesTo(ev core.Event) bool {
	return ev.ToolCall != nil && len(ev.Untrusted()) > 0
}

func (c *InjectedCallCheck) Configure(params map[string]any) error {
	if v, ok := numberOf(params["threshold"]); ok {
		c.Threshold = v
	}
	return nil
}

func (c *InjectedCallCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	v := core.Verdict{Label: core.LabelOK}
	defer func() { v.Latency = time.Since(start) }()
	if ev.ToolCall == nil {
		return v, nil
	}
	for _, i := range ev.Untrusted() {
		doc := ev.Context[i]
		hits := injection.Scan(doc.Content, true)
		score := injection.Score(hits)
		if score < c.Threshold {
			continue
		}
		// The call is attributed to the content when the content names the tool
		// or one of the argument values it carries. Without that link the
		// injection alone is reported by injection_indirect, not here.
		mentions := mentionsCall(doc.Content, ev.ToolCall)
		if len(mentions) == 0 {
			continue
		}
		if combined := combine(score, 0.8); combined > v.Score {
			v.Score = combined
		}
		v.Label = "tool_call_from_injection"
		v.Evidence = append(v.Evidence, core.Span{
			Field: core.FieldContext,
			Index: i,
			Start: mentions[0].start,
			End:   mentions[0].end,
			Text:  clip(doc.Content[mentions[0].start:mentions[0].end], 200),
			Note:  fmt.Sprintf("%s mentions %s (source %s, injection score %.2f)", mentions[0].what, ev.ToolCall.Name, doc.Source, score),
		})
	}
	return v, nil
}

type mention struct {
	what       string
	start, end int
}

func mentionsCall(content string, call *core.ToolCall) []mention {
	lower := strings.ToLower(content)
	var out []mention
	if i := strings.Index(lower, strings.ToLower(call.Name)); i >= 0 {
		out = append(out, mention{what: "tool name", start: i, end: i + len(call.Name)})
	}
	names := make([]string, 0, len(call.Args))
	for name := range call.Args {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s, ok := call.Args[name].(string)
		if !ok || len(s) < 4 {
			continue
		}
		if i := strings.Index(lower, strings.ToLower(s)); i >= 0 {
			out = append(out, mention{what: "argument " + name, start: i, end: i + len(s)})
		}
	}
	return out
}

func combine(a, b float64) float64 {
	s := 1 - (1-a)*(1-b)
	if s > 0.99 {
		s = 0.99
	}
	return s
}

func numberOf(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func stringList(params map[string]any, key string) ([]string, error) {
	raw, ok := params[key]
	if !ok {
		return nil, nil
	}
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("toolcall: %s must be a list of strings", key)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("toolcall: %s must be a list of strings", key)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
