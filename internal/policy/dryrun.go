package policy

import (
	"sort"

	"github.com/sagnikc395/cerberus/internal/core"
)

// Sample is one historical event with the verdicts that were recorded for it.
// A dry run replays the stored verdicts rather than re-running the checks, so
// the diff isolates the policy change from detector drift.
type Sample struct {
	Event   core.Event
	Results []core.Result
}

// Change is one event whose action differs between two policy versions.
type Change struct {
	EventID string `json:"event_id"`
	Agent   string `json:"agent"`
	From    Action `json:"from"`
	To      Action `json:"to"`
	// Reason names the checks that drove the new action.
	Reason []string `json:"reason,omitempty"`
}

// DryRun is the result of replaying two policy versions over the same traffic.
type DryRun struct {
	Agent        string         `json:"agent"`
	FromVersion  int            `json:"from_version"`
	ToVersion    int            `json:"to_version"`
	Events       int            `json:"events"`
	FromCounts   map[Action]int `json:"from_counts"`
	ToCounts     map[Action]int `json:"to_counts"`
	Changes      []Change       `json:"changes"`
	NewlyBlocked int            `json:"newly_blocked"`
	NewlyAllowed int            `json:"newly_allowed"`
	NewlyQueued  int            `json:"newly_queued_for_review"`
}

// Replay evaluates both versions over the same samples and reports what the
// change would have done. This is what "policy dry-run --since 7d" prints.
func Replay(from, to *Policy, samples []Sample) DryRun {
	out := DryRun{
		Agent:       to.Agent,
		FromVersion: 0,
		ToVersion:   to.Version,
		FromCounts:  map[Action]int{},
		ToCounts:    map[Action]int{},
	}
	if from != nil {
		out.FromVersion = from.Version
	}
	for _, s := range samples {
		before := Decision{Action: ActionAllow}
		if from != nil {
			before = from.Evaluate(s.Event, s.Results)
		}
		after := to.Evaluate(s.Event, s.Results)
		out.Events++
		out.FromCounts[before.Action]++
		out.ToCounts[after.Action]++
		if before.Action == after.Action {
			continue
		}
		change := Change{EventID: s.Event.ID, Agent: s.Event.AgentID, From: before.Action, To: after.Action}
		seen := map[string]bool{}
		for _, v := range after.Violations {
			if v.Action == after.Action && !seen[v.Check] {
				seen[v.Check] = true
				change.Reason = append(change.Reason, v.Check)
			}
		}
		sort.Strings(change.Reason)
		out.Changes = append(out.Changes, change)
		switch {
		case Blocking(after.Action) && !Blocking(before.Action):
			out.NewlyBlocked++
		case !Blocking(after.Action) && Blocking(before.Action):
			out.NewlyAllowed++
		}
		if NeedsReview(after.Action) && !NeedsReview(before.Action) {
			out.NewlyQueued++
		}
	}
	return out
}
