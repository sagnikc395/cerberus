package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/policy"
)

// Memory is an in-process store. It backs the tests, `make demo` without
// Postgres, and the eval harness, which needs a store but no durability.
type Memory struct {
	mu          sync.RWMutex
	evaluations map[string]Evaluation
	order       []string
	reviews     map[string]Review
	reviewOrder []string
	sessions    map[string]core.SessionState
}

// NewMemory returns an empty in-process store.
func NewMemory() *Memory {
	return &Memory{
		evaluations: map[string]Evaluation{},
		reviews:     map[string]Review{},
		sessions:    map[string]core.SessionState{},
	}
}

func (m *Memory) SaveEvaluation(_ context.Context, e Evaluation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.evaluations[e.EventID]; !exists {
		m.order = append(m.order, e.EventID)
	}
	m.evaluations[e.EventID] = e
	return nil
}

func (m *Memory) Evaluation(_ context.Context, eventID string) (Evaluation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.evaluations[eventID]
	if !ok {
		return Evaluation{}, fmt.Errorf("%w: event %s", ErrNotFound, eventID)
	}
	return e, nil
}

func (m *Memory) ListEvaluations(_ context.Context, f EventFilter) ([]Evaluation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Evaluation, 0, len(m.order))
	// Newest first, which is the order both the dashboard and a dry run want.
	for i := len(m.order) - 1; i >= 0; i-- {
		e := m.evaluations[m.order[i]]
		if f.Agent != "" && e.Agent != f.Agent {
			continue
		}
		if !f.Since.IsZero() && e.ReceivedAt.Before(f.Since) {
			continue
		}
		if f.FlaggedOnly && len(e.Decision.Violations) == 0 {
			continue
		}
		out = append(out, e)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

func (m *Memory) EnqueueReview(_ context.Context, r Review) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.reviews[r.ID]; exists {
		return nil // idempotent: a replayed workflow must not queue twice
	}
	m.reviews[r.ID] = r
	m.reviewOrder = append(m.reviewOrder, r.ID)
	return nil
}

func (m *Memory) Review(_ context.Context, id string) (Review, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.reviews[id]
	if !ok {
		return Review{}, fmt.Errorf("%w: review %s", ErrNotFound, id)
	}
	return r, nil
}

func (m *Memory) ListReviews(_ context.Context, f ReviewFilter) ([]Review, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Review, 0, len(m.reviewOrder))
	for _, id := range m.reviewOrder {
		r := m.reviews[id]
		if f.Agent != "" && r.Agent != f.Agent {
			continue
		}
		if f.State != "" && r.State != f.State {
			continue
		}
		out = append(out, r)
	}
	// Most severe first, then oldest, so the queue drains in the order that
	// matters rather than the order it arrived.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (m *Memory) DecideReview(_ context.Context, id string, d ReviewDecision) (Review, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reviews[id]
	if !ok {
		return Review{}, fmt.Errorf("%w: review %s", ErrNotFound, id)
	}
	if r.State != ReviewPending {
		return Review{}, fmt.Errorf("store: review %s is already %s", id, r.State)
	}
	now := time.Now().UTC()
	r.State = d.State
	r.Reviewer = d.Reviewer
	r.Notes = d.Notes
	r.Labels = d.Labels
	r.DecidedAt = &now
	m.reviews[id] = r
	return r, nil
}

func (m *Memory) AdvanceSession(_ context.Context, ev core.Event) (core.SessionState, error) {
	if ev.SessionID == "" {
		return ev.Session, nil
	}
	key := ev.AgentID + "/" + ev.SessionID
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, visible := fold(m.sessions[key], ev)
	m.sessions[key] = stored
	return visible, nil
}

// fold advances a session's rolling state by one event and returns the state
// the checks are given: everything spent before this event, plus this event's
// own turn, so a loop is caught on the turn that crosses the limit rather than
// the one after it. The event's own tokens are added to the stored rollup but
// not to what the checks see, which keeps a check a function of prior history.
func fold(state core.SessionState, ev core.Event) (stored, visible core.SessionState) {
	if state.StartedAt.IsZero() {
		state.StartedAt = ev.CreatedAt
	}
	visible = state
	visible.TurnCount = state.TurnCount + 1

	state.TurnCount++
	state.TokensSpent += ev.Usage.Total()
	state.CostSpentUSD += ev.Usage.CostUSD
	if ev.ToolCall != nil {
		state.RecentCalls = append(state.RecentCalls, *ev.ToolCall)
		if len(state.RecentCalls) > recentCallWindow {
			state.RecentCalls = state.RecentCalls[len(state.RecentCalls)-recentCallWindow:]
		}
	}
	return state, visible
}

func (m *Memory) LabelStats(_ context.Context, since time.Time) ([]LabelStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byKey := map[string]*LabelStats{}
	for _, r := range m.reviews {
		if r.DecidedAt == nil || r.DecidedAt.Before(since) {
			continue
		}
		for _, l := range r.Labels {
			key := l.Check + "@" + l.Version
			st := byKey[key]
			if st == nil {
				st = &LabelStats{Check: l.Check, Version: l.Version}
				byKey[key] = st
			}
			switch l.Label {
			case LabelTruePositive:
				st.TruePositives++
			case LabelFalsePositive:
				st.FalsePositives++
			default:
				st.Unsure++
			}
		}
	}
	out := make([]LabelStats, 0, len(byKey))
	for _, st := range byKey {
		if n := st.TruePositives + st.FalsePositives; n > 0 {
			st.Precision = float64(st.TruePositives) / float64(n)
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Check != out[j].Check {
			return out[i].Check < out[j].Check
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

func (m *Memory) Close() error { return nil }

// severityRank orders the queue. It mirrors the policy package's ordering
// without importing its unexported table.
func severityRank(s policy.Severity) int {
	switch s {
	case policy.SeverityCritical:
		return 4
	case policy.SeverityHigh:
		return 3
	case policy.SeverityMedium:
		return 2
	case policy.SeverityLow:
		return 1
	}
	return 0
}
