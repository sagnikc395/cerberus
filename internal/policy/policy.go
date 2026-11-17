// Package policy turns verdicts into actions. A policy belongs to one agent,
// carries a version, and is a pure function of the event and the verdicts, so
// a new version can be replayed against historical traffic before it is
// enabled.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sagnikc395/cerberus/internal/core"
	"gopkg.in/yaml.v3"
)

// Action is what the control plane does about a flagged event.
type Action string

const (
	// ActionAllow records nothing beyond metrics.
	ActionAllow Action = "allow"
	// ActionLog stores the violation.
	ActionLog Action = "log"
	// ActionAlert stores it and notifies the on-call channel.
	ActionAlert Action = "alert"
	// ActionRedact stores it with the offending spans masked and tells the
	// agent to send the redacted text instead.
	ActionRedact Action = "redact"
	// ActionRequireHumanApproval parks the event in the review queue and holds
	// the agent until a reviewer decides.
	ActionRequireHumanApproval Action = "require_human_approval"
	// ActionQuarantine stops the session and parks it for review.
	ActionQuarantine Action = "quarantine"
	// ActionBlock refuses the event outright.
	ActionBlock Action = "block"
)

// severity of a violation, used for alert routing and review priority.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var actionRank = map[Action]int{
	ActionAllow:                0,
	ActionLog:                  1,
	ActionAlert:                2,
	ActionRedact:               3,
	ActionRequireHumanApproval: 4,
	ActionQuarantine:           5,
	ActionBlock:                6,
}

var severityRank = map[Severity]int{
	SeverityInfo: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Blocking reports whether the action stops the agent from proceeding.
func Blocking(a Action) bool {
	switch a {
	case ActionBlock, ActionQuarantine, ActionRequireHumanApproval:
		return true
	}
	return false
}

// NeedsReview reports whether the action parks the event in the review queue.
func NeedsReview(a Action) bool {
	switch a {
	case ActionRequireHumanApproval, ActionQuarantine:
		return true
	}
	return false
}

// Condition narrows a rule to a subset of traffic. Every field set must match.
type Condition struct {
	Tool     string            `yaml:"tool,omitempty" json:"tool,omitempty"`
	Kind     string            `yaml:"kind,omitempty" json:"kind,omitempty"`
	Label    string            `yaml:"label,omitempty" json:"label,omitempty"`
	ScoreGt  *float64          `yaml:"score_gt,omitempty" json:"score_gt,omitempty"`
	ScoreLt  *float64          `yaml:"score_lt,omitempty" json:"score_lt,omitempty"`
	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	// Args compares the tool call's arguments. Keys are "<arg>_gt", "<arg>_lt",
	// "<arg>_eq", which is how the README's amount_gt: 500 is expressed.
	Args map[string]any `yaml:",inline" json:"args,omitempty"`
}

// Rule maps one check's verdict to an action.
type Rule struct {
	// Check is the check name, optionally pinned to a version with "name@1.2.0".
	Check string `yaml:"check" json:"check"`
	// When narrows the rule. A rule with no condition matches any flagged
	// verdict from that check.
	When *Condition `yaml:"when,omitempty" json:"when,omitempty"`
	// MinScore is the verdict score the rule needs. Zero means any flag.
	MinScore float64 `yaml:"min_score,omitempty" json:"min_score,omitempty"`
	// Severity is attached to the violation this rule produces.
	Severity Severity `yaml:"severity,omitempty" json:"severity,omitempty"`
	Action   Action   `yaml:"action" json:"action"`
	// Params configure the check itself for this agent (allowlists, bounds,
	// thresholds). They are applied when the engine builds the agent's checks.
	Params map[string]any `yaml:"params,omitempty" json:"params,omitempty"`
	// Notes is free text shown to reviewers alongside the violation.
	Notes string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// Policy is one agent's versioned rule set.
type Policy struct {
	Agent   string `yaml:"agent" json:"agent"`
	Version int    `yaml:"version" json:"version"`
	// DefaultAction applies to a flagged verdict no rule matched. It defaults
	// to log: a detector firing with no rule for it is still worth storing.
	DefaultAction Action `yaml:"default_action,omitempty" json:"default_action,omitempty"`
	// Disabled names checks this agent does not run at all.
	Disabled []string `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Rules    []Rule   `yaml:"rules" json:"rules"`
}

// Parse reads one policy document.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.DefaultAction == "" {
		p.DefaultAction = ActionLog
	}
	return &p, nil
}

// Validate rejects a policy the engine could not apply. It runs at load time
// and in CI, so a typo in an action never reaches traffic.
func (p *Policy) Validate() error {
	if p.Agent == "" {
		return fmt.Errorf("policy: agent is required")
	}
	if p.Version <= 0 {
		return fmt.Errorf("policy: %s: version must be a positive integer", p.Agent)
	}
	if p.DefaultAction != "" {
		if _, ok := actionRank[p.DefaultAction]; !ok {
			return fmt.Errorf("policy: %s: unknown default_action %q", p.Agent, p.DefaultAction)
		}
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy: %s v%d: at least one rule is required", p.Agent, p.Version)
	}
	for i, r := range p.Rules {
		if r.Check == "" {
			return fmt.Errorf("policy: %s v%d: rule %d has no check", p.Agent, p.Version, i)
		}
		if _, ok := actionRank[r.Action]; !ok {
			return fmt.Errorf("policy: %s v%d: rule %d (%s) has unknown action %q", p.Agent, p.Version, i, r.Check, r.Action)
		}
		if r.Severity != "" {
			if _, ok := severityRank[r.Severity]; !ok {
				return fmt.Errorf("policy: %s v%d: rule %d (%s) has unknown severity %q", p.Agent, p.Version, i, r.Check, r.Severity)
			}
		}
		if r.MinScore < 0 || r.MinScore > 1 {
			return fmt.Errorf("policy: %s v%d: rule %d (%s) min_score must be between 0 and 1", p.Agent, p.Version, i, r.Check)
		}
	}
	return nil
}

// Violation is one rule firing on one verdict.
type Violation struct {
	Check    string      `json:"check"`
	Version  string      `json:"check_version"`
	Label    string      `json:"label"`
	Score    float64     `json:"score"`
	Action   Action      `json:"action"`
	Severity Severity    `json:"severity"`
	Rule     int         `json:"rule_index"`
	Notes    string      `json:"notes,omitempty"`
	Evidence []core.Span `json:"evidence,omitempty"`
}

// Decision is the policy's output for one event.
type Decision struct {
	Agent         string      `json:"agent"`
	PolicyVersion int         `json:"policy_version"`
	Action        Action      `json:"action"`
	Severity      Severity    `json:"severity"`
	Violations    []Violation `json:"violations,omitempty"`
}

// Evaluate maps verdicts to an action. The strongest action wins, so a
// quarantine rule is never softened by a log rule that also matched.
func (p *Policy) Evaluate(ev core.Event, results []core.Result) Decision {
	d := Decision{Agent: p.Agent, PolicyVersion: p.Version, Action: ActionAllow}
	for _, res := range results {
		if res.Skipped || !res.Verdict.Flagged() {
			continue
		}
		matched := false
		for i, rule := range p.Rules {
			if !ruleMatches(rule, ev, res) {
				continue
			}
			matched = true
			v := Violation{
				Check:    res.Check,
				Version:  res.Version,
				Label:    res.Verdict.Label,
				Score:    res.Verdict.Score,
				Action:   rule.Action,
				Severity: rule.Severity,
				Rule:     i,
				Notes:    rule.Notes,
				Evidence: res.Verdict.Evidence,
			}
			if v.Severity == "" {
				v.Severity = inferSeverity(res.Verdict.Score)
			}
			d.Violations = append(d.Violations, v)
			if actionRank[rule.Action] > actionRank[d.Action] {
				d.Action = rule.Action
			}
			if severityRank[v.Severity] > severityRank[d.Severity] {
				d.Severity = v.Severity
			}
		}
		if matched {
			continue
		}
		// A check fired and no rule covers it: fall back to the default action
		// rather than discarding the finding.
		v := Violation{
			Check:    res.Check,
			Version:  res.Version,
			Label:    res.Verdict.Label,
			Score:    res.Verdict.Score,
			Action:   p.DefaultAction,
			Severity: inferSeverity(res.Verdict.Score),
			Rule:     -1,
			Notes:    "no rule for this check; default_action applied",
			Evidence: res.Verdict.Evidence,
		}
		d.Violations = append(d.Violations, v)
		if actionRank[p.DefaultAction] > actionRank[d.Action] {
			d.Action = p.DefaultAction
		}
		if severityRank[v.Severity] > severityRank[d.Severity] {
			d.Severity = v.Severity
		}
	}
	sort.SliceStable(d.Violations, func(i, j int) bool {
		return actionRank[d.Violations[i].Action] > actionRank[d.Violations[j].Action]
	})
	return d
}

func inferSeverity(score float64) Severity {
	switch {
	case score >= 0.9:
		return SeverityHigh
	case score >= 0.6:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityInfo
}

func ruleMatches(r Rule, ev core.Event, res core.Result) bool {
	name, version, pinned := strings.Cut(r.Check, "@")
	if name != res.Check {
		return false
	}
	if pinned && version != res.Version {
		return false
	}
	if res.Verdict.Score < r.MinScore {
		return false
	}
	if r.When == nil {
		return true
	}
	return conditionMatches(*r.When, ev, res)
}

func conditionMatches(c Condition, ev core.Event, res core.Result) bool {
	if c.Kind != "" && string(ev.Kind) != c.Kind {
		return false
	}
	if c.Label != "" && c.Label != res.Verdict.Label {
		return false
	}
	if c.ScoreGt != nil && !(res.Verdict.Score > *c.ScoreGt) {
		return false
	}
	if c.ScoreLt != nil && !(res.Verdict.Score < *c.ScoreLt) {
		return false
	}
	for k, want := range c.Metadata {
		if ev.Metadata[k] != want {
			return false
		}
	}
	if c.Tool != "" {
		if ev.ToolCall == nil || ev.ToolCall.Name != c.Tool {
			return false
		}
	}
	for key, want := range c.Args {
		if !argMatches(ev, key, want) {
			return false
		}
	}
	return true
}

// argMatches implements the "<arg>_gt" family. An argument the call does not
// carry never matches, so a bound cannot be dodged by omitting the field.
func argMatches(ev core.Event, key string, want any) bool {
	if ev.ToolCall == nil {
		return false
	}
	arg, op, found := reverseSuffix(key)
	if !found {
		return false
	}
	have, ok := numberOf(ev.ToolCall.Args[arg])
	threshold, okWant := numberOf(want)
	if !ok || !okWant {
		if op != "eq" {
			return false
		}
		s, isStr := ev.ToolCall.Args[arg].(string)
		w, isWStr := want.(string)
		return isStr && isWStr && s == w
	}
	switch op {
	case "gt":
		return have > threshold
	case "gte":
		return have >= threshold
	case "lt":
		return have < threshold
	case "lte":
		return have <= threshold
	case "eq":
		return have == threshold
	}
	return false
}

// reverseSuffix splits "amount_gt" into "amount" and "gt". The comparison
// suffix is the last underscore-separated token, so argument names may contain
// underscores.
func reverseSuffix(key string) (arg, op string, ok bool) {
	i := strings.LastIndexByte(key, '_')
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

func numberOf(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}
