package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/store"
)

func reviewCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("review needs a subcommand: list or decide")
	}
	switch args[0] {
	case "list":
		return reviewList(ctx, args[1:])
	case "decide":
		return reviewDecide(ctx, args[1:])
	}
	return fmt.Errorf("unknown review subcommand %q", args[0])
}

func reviewList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("review list", flag.ContinueOnError)
	url := fs.String("url", "", "control plane URL")
	state := fs.String("state", "pending", "pending, approved, rejected, expired or all")
	agent := fs.String("agent", "", "only this agent")
	limit := fs.Int("limit", 25, "maximum items")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var out struct {
		Reviews []store.Review `json:"reviews"`
		Count   int            `json:"count"`
	}
	path := fmt.Sprintf("/v1/reviews?state=%s&agent=%s&limit=%d", *state, *agent, *limit)
	if err := newClient(*url).do(ctx, "GET", path, nil, &out); err != nil {
		return err
	}
	if out.Count == 0 {
		fmt.Println("the queue is empty")
		return nil
	}
	fmt.Printf("%-34s %-16s %-10s %-22s %s\n", "ID", "AGENT", "SEVERITY", "ACTION", "WAITING")
	for _, r := range out.Reviews {
		fmt.Printf("%-34s %-16s %-10s %-22s %s\n", r.ID, r.Agent, r.Severity, r.Action,
			time.Since(r.CreatedAt).Round(time.Second))
		for _, v := range r.Violations {
			fmt.Printf("    %-26s score %.2f  %s\n", v.Check, v.Score, firstEvidence(v.Evidence))
		}
	}
	return nil
}

func firstEvidence(spans []core.Span) string {
	if len(spans) == 0 {
		return ""
	}
	note := spans[0].Note
	if note == "" {
		note = spans[0].Text
	}
	if len(note) > 90 {
		note = note[:90] + "…"
	}
	return note
}

func reviewDecide(ctx context.Context, args []string) error {
	// The id comes first, before the flags: Go's flag package stops parsing at
	// the first positional argument, so it is taken off the front by hand.
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("review decide", flag.ContinueOnError)
	url := fs.String("url", "", "control plane URL")
	state := fs.String("state", "", "approved or rejected")
	reviewer := fs.String("reviewer", "", "who decided")
	notes := fs.String("notes", "", "free text kept with the decision")
	var labels labelFlags
	fs.Var(&labels, "label", "check=true_positive|false_positive|unsure, repeatable: this is what feeds the eval set")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if id == "" {
		if fs.NArg() != 1 {
			return fmt.Errorf("review decide needs a review id")
		}
		id = fs.Arg(0)
	}
	if *state == "" || *reviewer == "" {
		return fmt.Errorf("--state and --reviewer are required")
	}
	decision := store.ReviewDecision{
		State:    store.ReviewState(*state),
		Reviewer: *reviewer,
		Notes:    *notes,
		Labels:   labels.labels,
	}
	var out store.Review
	if err := newClient(*url).do(ctx, "POST", "/v1/reviews/"+id+"/decision", decision, &out); err != nil {
		return err
	}
	fmt.Printf("%s is now %s (reviewer %s, %d label(s))\n", out.ID, out.State, out.Reviewer, len(out.Labels))
	return nil
}

// labelFlags collects repeated --label check=verdict pairs.
type labelFlags struct {
	labels []store.CheckLabel
}

func (l *labelFlags) String() string { return fmt.Sprintf("%d labels", len(l.labels)) }

func (l *labelFlags) Set(v string) error {
	check, label, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("want check=label, got %q", v)
	}
	version := ""
	if name, ver, pinned := strings.Cut(check, "@"); pinned {
		check, version = name, ver
	}
	switch store.Label(label) {
	case store.LabelTruePositive, store.LabelFalsePositive, store.LabelUnsure:
	default:
		return fmt.Errorf("unknown label %q", label)
	}
	l.labels = append(l.labels, store.CheckLabel{Check: check, Version: version, Label: store.Label(label)})
	return nil
}
