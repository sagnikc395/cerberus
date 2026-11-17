package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sagnikc395/cerberus/internal/checks/cost"
	"github.com/sagnikc395/cerberus/internal/checks/groundedness"
	"github.com/sagnikc395/cerberus/internal/checks/injection"
	"github.com/sagnikc395/cerberus/internal/checks/pii"
	"github.com/sagnikc395/cerberus/internal/checks/secrets"
	"github.com/sagnikc395/cerberus/internal/checks/toolcall"
	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/policy"
)

// DefaultRegistry is the set of checks the engine ships with. A new detector
// is added here with its own version, and the old one stays registered so the
// two run side by side on the same traffic until the eval report says the new
// one is better.
func DefaultRegistry() *core.Registry {
	r := core.NewRegistry()
	r.MustRegister(pii.NewPromptCheck())
	r.MustRegister(pii.NewLeakCheck())
	r.MustRegister(secrets.NewLeakCheck())
	r.MustRegister(injection.NewDirectCheck())
	r.MustRegister(injection.NewIndirectCheck())
	r.MustRegister(toolcall.NewAllowlistCheck())
	r.MustRegister(toolcall.NewBoundsCheck())
	r.MustRegister(toolcall.NewInjectedCallCheck())
	r.MustRegister(cost.NewBudgetCheck())
	r.MustRegister(cost.NewLoopCheck())
	r.MustRegister(groundedness.New())
	return r
}

// BuildPlan is buildPlan for callers outside the engine: the CLI validates a
// policy by building the plan it would produce.
func BuildPlan(reg *core.Registry, p *policy.Policy) (Plan, error) { return buildPlan(reg, p) }

// Plan is the configured set of checks for one agent, in execution order.
type Plan struct {
	Agent  string
	Checks []core.Check
}

// buildPlan turns a policy into the checks an agent runs. Every check in the
// registry runs unless the policy disables it, and a rule's params configure
// the copy this agent gets.
func buildPlan(reg *core.Registry, p *policy.Policy) (Plan, error) {
	disabled := map[string]bool{}
	if p != nil {
		for _, name := range p.Disabled {
			disabled[name] = true
		}
	}
	// A rule may pin a version ("pii_leak@1.0.0"); that pin decides which copy
	// of the detector this agent runs.
	pinned := map[string]string{}
	params := map[string]map[string]any{}
	if p != nil {
		for _, rule := range p.Rules {
			name, version, isPinned := strings.Cut(rule.Check, "@")
			if isPinned {
				pinned[name] = version
			}
			if len(rule.Params) == 0 {
				continue
			}
			merged := params[name]
			if merged == nil {
				merged = map[string]any{}
				params[name] = merged
			}
			for k, v := range rule.Params {
				merged[k] = v
			}
		}
	}

	plan := Plan{}
	if p != nil {
		plan.Agent = p.Agent
	}
	seen := map[string]bool{}
	for _, name := range reg.Names() {
		if disabled[name] {
			continue
		}
		proto, ok := reg.Get(name, pinned[name])
		if !ok {
			return Plan{}, fmt.Errorf("engine: %s pins %s@%s, which is not registered", plan.Agent, name, pinned[name])
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		c := core.Clone(proto)
		if cfg, ok := c.(core.Configurable); ok {
			if ps := params[name]; len(ps) > 0 {
				if err := cfg.Configure(ps); err != nil {
					return Plan{}, fmt.Errorf("engine: %s: configure %s: %w", plan.Agent, name, err)
				}
			}
		} else if len(params[name]) > 0 {
			return Plan{}, fmt.Errorf("engine: %s: check %s takes no params", plan.Agent, name)
		}
		plan.Checks = append(plan.Checks, c)
	}
	sort.SliceStable(plan.Checks, func(i, j int) bool {
		if plan.Checks[i].Tier() != plan.Checks[j].Tier() {
			return plan.Checks[i].Tier() < plan.Checks[j].Tier()
		}
		return plan.Checks[i].Name() < plan.Checks[j].Name()
	})
	return plan, nil
}

// tiers groups a plan's checks into ascending tiers.
func tiers(checks []core.Check) [][]core.Check {
	var out [][]core.Check
	var current []core.Check
	var tier core.Tier
	for _, c := range checks {
		if len(current) > 0 && c.Tier() != tier {
			out = append(out, current)
			current = nil
		}
		tier = c.Tier()
		current = append(current, c)
	}
	if len(current) > 0 {
		out = append(out, current)
	}
	return out
}
