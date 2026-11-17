package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/engine"
	"github.com/sagnikc395/cerberus/internal/policy"
	"github.com/sagnikc395/cerberus/internal/store"
	"gopkg.in/yaml.v3"
)

func policyCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy needs a subcommand: validate, show or dry-run")
	}
	switch args[0] {
	case "validate":
		return policyValidate(args[1:])
	case "show":
		return policyShow(args[1:])
	case "dry-run":
		return policyDryRun(ctx, args[1:])
	}
	return fmt.Errorf("unknown policy subcommand %q", args[0])
}

// policyValidate parses every policy and builds each agent's check plan, which
// is what catches a rule naming a check that does not exist or params a check
// will not accept. CI runs this on every change.
func policyValidate(args []string) error {
	dir := "policies"
	if len(args) > 0 {
		dir = args[0]
	}
	set, err := policy.LoadDir(dir)
	if err != nil {
		return err
	}
	registry := engine.DefaultRegistry()
	known := map[string]bool{}
	for _, name := range registry.Names() {
		known[name] = true
	}
	problems := 0
	for _, agent := range set.Agents() {
		for _, version := range set.Versions(agent) {
			p, _ := set.Version(agent, version)
			for i, rule := range p.Rules {
				name := rule.Check
				if at := strings.IndexByte(name, '@'); at >= 0 {
					name = name[:at]
				}
				if !known[name] {
					fmt.Printf("  %s v%d rule %d: no check named %q is registered\n", agent, version, i, name)
					problems++
				}
			}
			if _, err := buildPlanFor(registry, p); err != nil {
				fmt.Printf("  %s v%d: %v\n", agent, version, err)
				problems++
				continue
			}
			fmt.Printf("ok  %s v%d (%d rules)\n", agent, version, len(p.Rules))
		}
	}
	if problems > 0 {
		return fmt.Errorf("%d policy problem(s)", problems)
	}
	return nil
}

// buildPlanFor exercises the engine's plan builder without starting an engine.
func buildPlanFor(reg *core.Registry, p *policy.Policy) (engine.Plan, error) {
	return engine.BuildPlan(reg, p)
}

func policyShow(args []string) error {
	var agent string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		agent, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
	dir := fs.String("policies", "policies", "policy directory")
	version := fs.Int("version", 0, "version to show; 0 means the active one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if agent == "" {
		if fs.NArg() != 1 {
			return fmt.Errorf("policy show needs an agent name")
		}
		agent = fs.Arg(0)
	}
	set, err := policy.LoadDir(*dir)
	if err != nil {
		return err
	}
	var p *policy.Policy
	var ok bool
	if *version > 0 {
		p, ok = set.Version(agent, *version)
	} else {
		p, ok = set.Active(agent)
	}
	if !ok {
		return fmt.Errorf("no policy for %s", agent)
	}
	out, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	fmt.Printf("# %s, active version %d, loaded versions %v\n%s", agent, p.Version, set.Versions(agent), out)

	plan, err := buildPlanFor(engine.DefaultRegistry(), p)
	if err != nil {
		return err
	}
	fmt.Printf("\n# checks this agent runs\n")
	for _, c := range plan.Checks {
		fmt.Printf("# %-26s %-8s %s\n", c.Name(), c.Version(), c.Tier())
	}
	return nil
}

// policyDryRun replays a candidate policy over stored traffic and prints what
// would have changed. The stored verdicts are reused rather than re-running
// the checks, so the diff is the policy's effect alone.
func policyDryRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy dry-run", flag.ContinueOnError)
	path := fs.String("policy", "", "candidate policy file (required)")
	since := fs.String("since", "7d", "how far back to replay")
	limit := fs.Int("limit", 5000, "maximum events to replay")
	against := fs.Int("against", 0, "version to compare with; 0 uses the agent's active policy")
	dir := fs.String("policies", "policies", "directory holding the current policies")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	databaseURL := fs.String("database-url", os.Getenv("DATABASE_URL"), "Postgres URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("policy dry-run needs --policy FILE")
	}
	candidate, err := policy.LoadFile(*path)
	if err != nil {
		return err
	}
	window, err := core.ParseDuration(*since)
	if err != nil {
		return err
	}

	current, err := policy.LoadDir(*dir)
	if err != nil {
		return err
	}
	var baseline *policy.Policy
	if *against > 0 {
		baseline, _ = current.Version(candidate.Agent, *against)
		if baseline == nil {
			return fmt.Errorf("%s v%d is not loaded", candidate.Agent, *against)
		}
	} else {
		baseline, _ = current.Active(candidate.Agent)
	}

	if *databaseURL == "" {
		return fmt.Errorf("dry-run reads stored traffic: set DATABASE_URL or --database-url")
	}
	pg, err := store.OpenPostgres(ctx, *databaseURL)
	if err != nil {
		return err
	}
	defer pg.Close()

	evaluations, err := pg.ListEvaluations(ctx, store.EventFilter{
		Agent: candidate.Agent,
		Since: time.Now().Add(-window),
		Limit: *limit,
	})
	if err != nil {
		return err
	}
	samples := make([]policy.Sample, 0, len(evaluations))
	for _, e := range evaluations {
		samples = append(samples, policy.Sample{Event: e.Event, Results: e.Results})
	}
	report := policy.Replay(baseline, candidate, samples)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	printDryRun(report, window)
	return nil
}

func printDryRun(r policy.DryRun, window time.Duration) {
	fmt.Printf("%s: v%d -> v%d over %s of traffic (%d events)\n\n",
		r.Agent, r.FromVersion, r.ToVersion, window, r.Events)
	if r.Events == 0 {
		fmt.Println("no stored traffic in that window; nothing to compare")
		return
	}
	actions := map[policy.Action]bool{}
	for a := range r.FromCounts {
		actions[a] = true
	}
	for a := range r.ToCounts {
		actions[a] = true
	}
	names := make([]string, 0, len(actions))
	for a := range actions {
		names = append(names, string(a))
	}
	sort.Strings(names)
	fmt.Printf("%-24s %8s %8s %8s\n", "ACTION", "BEFORE", "AFTER", "DELTA")
	for _, name := range names {
		a := policy.Action(name)
		before, after := r.FromCounts[a], r.ToCounts[a]
		fmt.Printf("%-24s %8d %8d %+8d\n", name, before, after, after-before)
	}
	fmt.Printf("\n%d events change action: %d newly held, %d newly released, %d newly queued for review\n",
		len(r.Changes), r.NewlyBlocked, r.NewlyAllowed, r.NewlyQueued)

	shown := len(r.Changes)
	if shown > 20 {
		shown = 20
	}
	for _, c := range r.Changes[:shown] {
		fmt.Printf("  %s  %s -> %s  (%v)\n", c.EventID, c.From, c.To, c.Reason)
	}
	if len(r.Changes) > shown {
		fmt.Printf("  ... %d more\n", len(r.Changes)-shown)
	}
}

// planForAgent loads the policies and returns the plan one agent runs.
func planForAgent(reg *core.Registry, dir, agent string) (engine.Plan, error) {
	set, err := policy.LoadDir(dir)
	if err != nil {
		return engine.Plan{}, err
	}
	p, ok := set.Active(agent)
	if !ok {
		return engine.Plan{}, fmt.Errorf("no policy for %s", agent)
	}
	return engine.BuildPlan(reg, p)
}
