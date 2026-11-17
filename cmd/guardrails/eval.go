package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sagnikc395/cerberus/internal/engine"
	"github.com/sagnikc395/cerberus/internal/eval"
)

// evalCmd runs the harness. With --enforce it is the CI gate: the run fails if
// a check is below its threshold or below what the same version scored in the
// recorded baseline.
func evalCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	datasets := fs.String("datasets", "eval/datasets", "directory of .jsonl datasets")
	format := fs.String("format", "text", "text, md or json")
	thresholdPath := fs.String("thresholds", "eval/thresholds.yaml", "enforced accuracy contract")
	baselinePath := fs.String("baseline", "eval/baseline.json", "recorded baseline to compare against")
	enforce := fs.Bool("enforce", false, "exit non-zero when a check is below its threshold or baseline")
	update := fs.Bool("update-baseline", false, "record this run as the new baseline")
	out := fs.String("out", "", "also write the report to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cases, err := eval.LoadDir(*datasets)
	if err != nil {
		return err
	}
	report, err := eval.Run(ctx, engine.DefaultRegistry(), cases)
	if err != nil {
		return err
	}

	if err := render(os.Stdout, *format, report); err != nil {
		return err
	}
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := render(f, *format, report); err != nil {
			return err
		}
	}
	if *update {
		if err := eval.SaveBaseline(*baselinePath, report); err != nil {
			return err
		}
		fmt.Printf("\nbaseline written to %s\n", *baselinePath)
	}
	if !*enforce {
		return nil
	}

	thresholds, err := eval.LoadThresholds(*thresholdPath)
	if err != nil {
		return err
	}
	baseline, err := eval.LoadBaseline(*baselinePath)
	if err != nil {
		return err
	}
	failures := append(thresholds.Enforce(report), thresholds.CompareBaseline(baseline, report)...)
	if len(failures) == 0 {
		fmt.Printf("\nall enforced checks are within threshold and at or above baseline\n")
		return nil
	}
	fmt.Printf("\n%d accuracy failure(s):\n", len(failures))
	for _, f := range failures {
		fmt.Printf("  %s\n", f)
	}
	return fmt.Errorf("eval gate failed")
}

func render(w *os.File, format string, r eval.Report) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "md", "markdown":
		return r.Markdown(w)
	case "text", "":
		return r.Text(w)
	}
	return fmt.Errorf("unknown format %q", format)
}

func checksCmd(args []string) error {
	fs := flag.NewFlagSet("checks", flag.ContinueOnError)
	agent := fs.String("agent", "", "show the checks this agent runs, after its policy is applied")
	dir := fs.String("policies", "policies", "policy directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	registry := engine.DefaultRegistry()
	if *agent == "" {
		fmt.Printf("%-28s %-22s %s\n", "CHECK", "VERSION", "TIER")
		for _, c := range registry.All() {
			fmt.Printf("%-28s %-22s %s\n", c.Name(), c.Version(), c.Tier())
		}
		return nil
	}
	plan, err := planForAgent(registry, *dir, *agent)
	if err != nil {
		return err
	}
	fmt.Printf("%-28s %-22s %s\n", "CHECK", "VERSION", "TIER")
	for _, c := range plan.Checks {
		fmt.Printf("%-28s %-22s %s\n", c.Name(), c.Version(), c.Tier())
	}
	return nil
}
