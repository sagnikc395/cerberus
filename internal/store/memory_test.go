package store

import (
	"context"
	"testing"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/policy"
)

func TestAdvanceSessionShowsPriorSpendAndThisTurn(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	ev := core.Event{ID: "e1", AgentID: "a", SessionID: "s", Kind: core.KindCompletion,
		CreatedAt: time.Now(), Usage: core.Usage{PromptTokens: 100, CompletionTokens: 50}}

	first, err := s.AdvanceSession(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if first.TokensSpent != 0 {
		t.Errorf("tokens visible on the first event = %d, want 0 (its own usage is not prior spend)", first.TokensSpent)
	}
	if first.TurnCount != 1 {
		t.Errorf("turn count = %d, want 1", first.TurnCount)
	}

	ev.ID = "e2"
	second, err := s.AdvanceSession(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if second.TokensSpent != 150 {
		t.Errorf("tokens = %d, want 150 from the first event", second.TokensSpent)
	}
	if second.TurnCount != 2 {
		t.Errorf("turn count = %d, want 2", second.TurnCount)
	}
}

func TestAdvanceSessionCarriesRecentCalls(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	call := core.ToolCall{Name: "lookup_order", Args: map[string]any{"order_id": "8812"}}
	for i := 0; i < 3; i++ {
		ev := core.Event{ID: string(rune('a' + i)), AgentID: "a", SessionID: "s", Kind: core.KindToolCall, ToolCall: &call}
		state, err := s.AdvanceSession(ctx, ev)
		if err != nil {
			t.Fatal(err)
		}
		if len(state.RecentCalls) != i {
			t.Fatalf("event %d saw %d prior calls, want %d", i, len(state.RecentCalls), i)
		}
	}
}

func TestEnqueueReviewIsIdempotentAndDecidedOnce(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	r := Review{ID: "review:1", EventID: "e1", Agent: "a", Action: policy.ActionQuarantine,
		Severity: policy.SeverityCritical, State: ReviewPending, CreatedAt: time.Now()}
	if err := s.EnqueueReview(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueReview(ctx, r); err != nil {
		t.Fatal(err)
	}
	pending, err := s.ListReviews(ctx, ReviewFilter{State: ReviewPending})
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("queue holds %d items, want 1", len(pending))
	}
	if _, err := s.DecideReview(ctx, r.ID, ReviewDecision{State: ReviewApproved, Reviewer: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideReview(ctx, r.ID, ReviewDecision{State: ReviewRejected, Reviewer: "b"}); err == nil {
		t.Error("a decided item was decided again")
	}
}

func TestListReviewsOrdersBySeverityThenAge(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	base := time.Now()
	items := []Review{
		{ID: "r-low", Agent: "a", Severity: policy.SeverityLow, State: ReviewPending, CreatedAt: base},
		{ID: "r-crit", Agent: "a", Severity: policy.SeverityCritical, State: ReviewPending, CreatedAt: base.Add(time.Minute)},
		{ID: "r-high", Agent: "a", Severity: policy.SeverityHigh, State: ReviewPending, CreatedAt: base.Add(2 * time.Minute)},
	}
	for _, r := range items {
		if err := s.EnqueueReview(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListReviews(ctx, ReviewFilter{State: ReviewPending})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"r-crit", "r-high", "r-low"}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("queue order = %s, want %v", ids(got), want)
		}
	}
}

func ids(reviews []Review) []string {
	out := make([]string, 0, len(reviews))
	for _, r := range reviews {
		out = append(out, r.ID)
	}
	return out
}
