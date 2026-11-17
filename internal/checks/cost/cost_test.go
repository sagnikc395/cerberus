package cost

import (
	"context"
	"testing"

	"github.com/sagnikc395/cerberus/internal/core"
)

func TestBudgetCheckCountsPriorSpendPlusThisEvent(t *testing.T) {
	c := NewBudgetCheck()
	if err := c.Configure(map[string]any{"max_session_tokens": 1000.0}); err != nil {
		t.Fatal(err)
	}
	inside := core.Event{SessionID: "s", Usage: core.Usage{PromptTokens: 100},
		Session: core.SessionState{TokensSpent: 800}}
	if v, _ := c.Run(context.Background(), inside); v.Flagged() {
		t.Errorf("900 tokens against a 1000 budget was flagged: %+v", v)
	}
	over := core.Event{SessionID: "s", Usage: core.Usage{PromptTokens: 300},
		Session: core.SessionState{TokensSpent: 800}}
	v, _ := c.Run(context.Background(), over)
	if !v.Flagged() {
		t.Fatal("1100 tokens against a 1000 budget was not flagged")
	}
	if v.Score < 0.5 {
		t.Errorf("score = %v, want at least 0.5 for a breach", v.Score)
	}
}

func TestRepeatedCallNeedsIdenticalArguments(t *testing.T) {
	c := NewLoopCheck()
	if err := c.Configure(map[string]any{"repeat_threshold": 3.0}); err != nil {
		t.Fatal(err)
	}
	same := core.ToolCall{Name: "lookup_order", Args: map[string]any{"order_id": "8812"}}
	different := core.ToolCall{Name: "lookup_order", Args: map[string]any{"order_id": "1001"}}

	v, _ := c.Run(context.Background(), core.Event{SessionID: "s", ToolCall: &same,
		Session: core.SessionState{RecentCalls: []core.ToolCall{same, different}}})
	if v.Flagged() {
		t.Errorf("two identical calls under a threshold of three were flagged: %+v", v)
	}
	v, _ = c.Run(context.Background(), core.Event{SessionID: "s", ToolCall: &same,
		Session: core.SessionState{RecentCalls: []core.ToolCall{same, same, different}}})
	if !v.Flagged() || v.Label != "repeated_tool_call" {
		t.Errorf("three identical calls were not flagged: %+v", v)
	}
}

func TestConfigureRejectsAThresholdThatCannotRepeat(t *testing.T) {
	if err := NewLoopCheck().Configure(map[string]any{"repeat_threshold": 1.0}); err == nil {
		t.Error("a repeat threshold of one was accepted; it would flag every tool call")
	}
}
