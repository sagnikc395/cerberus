// Package cost holds the budget guardrails. They read the rolling session
// state the ingest API attaches to each event, so a single event is still
// enough to decide: no check reaches back into the store.
package cost

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
)

// BudgetCheck flags a session that has spent more tokens, or more money, than
// the agent is allowed for one session.
type BudgetCheck struct {
	MaxSessionTokens int
	MaxSessionUSD    float64
	Ver              string
}

// NewBudgetCheck returns the token-budget check with the defaults a small
// support agent can live with.
func NewBudgetCheck() *BudgetCheck {
	return &BudgetCheck{MaxSessionTokens: 120_000, MaxSessionUSD: 2.0, Ver: "1.0.0"}
}

func (c *BudgetCheck) Name() string    { return "token_budget" }
func (c *BudgetCheck) Version() string { return c.Ver }
func (c *BudgetCheck) Tier() core.Tier { return core.TierRegex }

// Configure reads {"max_session_tokens": 50000, "max_session_usd": 1.5}.
func (c *BudgetCheck) Configure(params map[string]any) error {
	if v, ok := number(params["max_session_tokens"]); ok {
		c.MaxSessionTokens = int(v)
	}
	if v, ok := number(params["max_session_usd"]); ok {
		c.MaxSessionUSD = v
	}
	return nil
}

func (c *BudgetCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	v := core.Verdict{Label: core.LabelOK}
	defer func() { v.Latency = time.Since(start) }()

	tokens := ev.Session.TokensSpent + ev.Usage.Total()
	spend := ev.Session.CostSpentUSD + ev.Usage.CostUSD

	if c.MaxSessionTokens > 0 && tokens > c.MaxSessionTokens {
		v.Label = "token_budget_breach"
		v.Score = ratioScore(float64(tokens), float64(c.MaxSessionTokens))
		v.Evidence = []core.Span{{
			Note: fmt.Sprintf("session %s spent %d tokens, budget %d", ev.SessionID, tokens, c.MaxSessionTokens),
			Text: strconv.Itoa(tokens) + " tokens",
		}}
		return v, nil
	}
	if c.MaxSessionUSD > 0 && spend > c.MaxSessionUSD {
		v.Label = "token_budget_breach"
		v.Score = ratioScore(spend, c.MaxSessionUSD)
		v.Evidence = []core.Span{{
			Note: fmt.Sprintf("session %s spent $%.4f, budget $%.2f", ev.SessionID, spend, c.MaxSessionUSD),
			Text: fmt.Sprintf("$%.4f", spend),
		}}
	}
	return v, nil
}

// ratioScore maps overspend to 0.5..0.99: at the budget it is a breach worth
// noting, at twice the budget it is as certain as the check gets.
func ratioScore(actual, budget float64) float64 {
	if budget <= 0 {
		return 0.5
	}
	over := actual/budget - 1
	s := 0.5 + over/2
	if s > 0.99 {
		return 0.99
	}
	if s < 0.5 {
		return 0.5
	}
	return s
}

// LoopCheck flags the two shapes of runaway agent: a session that keeps taking
// turns without finishing, and the same tool called with the same arguments
// over and over.
type LoopCheck struct {
	MaxTurns        int
	RepeatThreshold int
	Ver             string
}

// NewLoopCheck returns the runaway-loop check.
func NewLoopCheck() *LoopCheck {
	return &LoopCheck{MaxTurns: 40, RepeatThreshold: 3, Ver: "1.0.0"}
}

func (c *LoopCheck) Name() string    { return "runaway_loop" }
func (c *LoopCheck) Version() string { return c.Ver }
func (c *LoopCheck) Tier() core.Tier { return core.TierRegex }

// Configure reads {"max_turns": 30, "repeat_threshold": 4}.
func (c *LoopCheck) Configure(params map[string]any) error {
	if v, ok := number(params["max_turns"]); ok {
		c.MaxTurns = int(v)
	}
	if v, ok := number(params["repeat_threshold"]); ok {
		n := int(v)
		if n < 2 {
			return fmt.Errorf("cost: repeat_threshold must be at least 2")
		}
		c.RepeatThreshold = n
	}
	return nil
}

func (c *LoopCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	v := core.Verdict{Label: core.LabelOK}
	defer func() { v.Latency = time.Since(start) }()

	if ev.ToolCall != nil && c.RepeatThreshold > 0 {
		want := signature(*ev.ToolCall)
		repeats := 1 // the call on this event
		for _, prior := range ev.Session.RecentCalls {
			if signature(prior) == want {
				repeats++
			}
		}
		if repeats >= c.RepeatThreshold {
			v.Label = "repeated_tool_call"
			v.Score = ratioScore(float64(repeats), float64(c.RepeatThreshold))
			v.Evidence = []core.Span{{
				Field: core.FieldToolArgs,
				Text:  ev.ToolCall.Name + core.EncodeArgs(ev.ToolCall.Args),
				Note:  fmt.Sprintf("%s called %d times with identical arguments in session %s", ev.ToolCall.Name, repeats, ev.SessionID),
			}}
			return v, nil
		}
	}
	if c.MaxTurns > 0 && ev.Session.TurnCount > c.MaxTurns {
		v.Label = "runaway_loop"
		v.Score = ratioScore(float64(ev.Session.TurnCount), float64(c.MaxTurns))
		v.Evidence = []core.Span{{
			Note: fmt.Sprintf("session %s is on turn %d, limit %d", ev.SessionID, ev.Session.TurnCount, c.MaxTurns),
			Text: strconv.Itoa(ev.Session.TurnCount) + " turns",
		}}
	}
	return v, nil
}

// signature identifies a call by name and rendered arguments. EncodeArgs sorts
// keys, so argument order in the agent's JSON does not hide a repeat.
func signature(call core.ToolCall) string {
	return call.Name + "(" + core.EncodeArgs(call.Args) + ")"
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}
