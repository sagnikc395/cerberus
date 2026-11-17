package policy

import (
	"testing"

	"github.com/sagnikc395/cerberus/internal/core"
)

const refundPolicy = `
agent: refund-agent
version: 3
default_action: log
rules:
  - check: pii_leak
    severity: critical
    action: quarantine
  - check: tool_call_bounds
    when: { tool: issue_refund, amount_gt: 500 }
    action: require_human_approval
  - check: injection_indirect
    severity: high
    action: alert
`

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestParseRejectsUnknownAction(t *testing.T) {
	_, err := Parse([]byte("agent: a\nversion: 1\nrules:\n  - check: pii_leak\n    action: explode\n"))
	if err == nil {
		t.Fatal("an unknown action was accepted")
	}
}

func TestEvaluateTakesTheStrongestAction(t *testing.T) {
	p := mustParse(t, refundPolicy)
	ev := core.Event{ID: "e1", AgentID: "refund-agent", Kind: core.KindCompletion}
	results := []core.Result{
		{Check: "injection_indirect", Version: "1.0.0", Verdict: core.Verdict{Label: "injection_indirect", Score: 0.6}},
		{Check: "pii_leak", Version: "1.0.0", Verdict: core.Verdict{Label: "pii_leak", Score: 0.9}},
	}
	d := p.Evaluate(ev, results)
	if d.Action != ActionQuarantine {
		t.Errorf("action = %s, want quarantine", d.Action)
	}
	if d.Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical", d.Severity)
	}
	if len(d.Violations) != 2 {
		t.Errorf("got %d violations, want 2", len(d.Violations))
	}
	if d.Violations[0].Action != ActionQuarantine {
		t.Error("violations are not ordered by action strength")
	}
}

func TestConditionComparesToolArguments(t *testing.T) {
	p := mustParse(t, refundPolicy)
	results := []core.Result{{Check: "tool_call_bounds", Version: "1.0.0", Verdict: core.Verdict{Label: "tool_call_bounds", Score: 0.9}}}

	over := core.Event{ID: "e1", AgentID: "refund-agent", Kind: core.KindToolCall,
		ToolCall: &core.ToolCall{Name: "issue_refund", Args: map[string]any{"amount": 900.0}}}
	if got := p.Evaluate(over, results).Action; got != ActionRequireHumanApproval {
		t.Errorf("action for a $900 refund = %s, want require_human_approval", got)
	}

	// Below the threshold the rule does not match, so the default action applies.
	under := core.Event{ID: "e2", AgentID: "refund-agent", Kind: core.KindToolCall,
		ToolCall: &core.ToolCall{Name: "issue_refund", Args: map[string]any{"amount": 100.0}}}
	if got := p.Evaluate(under, results).Action; got != ActionLog {
		t.Errorf("action for a $100 refund = %s, want log", got)
	}

	// A different tool is not covered by the condition either.
	other := core.Event{ID: "e3", AgentID: "refund-agent", Kind: core.KindToolCall,
		ToolCall: &core.ToolCall{Name: "lookup_order", Args: map[string]any{"amount": 900.0}}}
	if got := p.Evaluate(other, results).Action; got != ActionLog {
		t.Errorf("action for another tool = %s, want log", got)
	}
}

func TestCleanVerdictsProduceNoViolations(t *testing.T) {
	p := mustParse(t, refundPolicy)
	ev := core.Event{ID: "e1", AgentID: "refund-agent"}
	d := p.Evaluate(ev, []core.Result{
		{Check: "pii_leak", Verdict: core.Verdict{Label: core.LabelOK}},
		{Check: "injection_indirect", Skipped: true},
	})
	if d.Action != ActionAllow || len(d.Violations) != 0 {
		t.Errorf("got %s with %d violations, want allow with none", d.Action, len(d.Violations))
	}
}

func TestReplayReportsWhatAPolicyChangeWouldDo(t *testing.T) {
	from := mustParse(t, refundPolicy)
	to := mustParse(t, `
agent: refund-agent
version: 4
default_action: log
rules:
  - check: pii_leak
    severity: critical
    action: quarantine
  - check: tool_call_bounds
    when: { tool: issue_refund, amount_gt: 200 }
    action: require_human_approval
  - check: injection_indirect
    severity: high
    action: require_human_approval
`)
	samples := []Sample{
		{
			Event:   core.Event{ID: "a", AgentID: "refund-agent", Kind: core.KindToolCall, ToolCall: &core.ToolCall{Name: "issue_refund", Args: map[string]any{"amount": 300.0}}},
			Results: []core.Result{{Check: "tool_call_bounds", Verdict: core.Verdict{Label: "tool_call_bounds", Score: 0.9}}},
		},
		{
			Event:   core.Event{ID: "b", AgentID: "refund-agent", Kind: core.KindToolResult},
			Results: []core.Result{{Check: "injection_indirect", Verdict: core.Verdict{Label: "injection_indirect", Score: 0.5}}},
		},
		{
			Event:   core.Event{ID: "c", AgentID: "refund-agent", Kind: core.KindPrompt},
			Results: []core.Result{{Check: "pii_prompt", Verdict: core.Verdict{Label: core.LabelOK}}},
		},
	}
	report := Replay(from, to, samples)
	if report.Events != 3 {
		t.Fatalf("replayed %d events, want 3", report.Events)
	}
	if len(report.Changes) != 2 {
		t.Fatalf("got %d changes, want 2: %+v", len(report.Changes), report.Changes)
	}
	if report.NewlyQueued != 2 || report.NewlyBlocked != 2 {
		t.Errorf("newly queued %d, newly blocked %d; want 2 and 2", report.NewlyQueued, report.NewlyBlocked)
	}
	if report.ToCounts[ActionRequireHumanApproval] != 2 {
		t.Errorf("after-counts = %+v", report.ToCounts)
	}
}
