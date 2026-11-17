package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/policy"
)

//go:embed schema.sql
var schemaFS embed.FS

// Postgres is the durable store. It shares the database with anchora, which
// keeps the engine's checkpoints, so an operator runs exactly one database.
type Postgres struct {
	pool *pgxpool.Pool
	// owned is true when this store opened the pool and must close it.
	owned bool
}

// OpenPostgres connects, applies the schema, and returns the store. The schema
// is idempotent, so every process may run it at startup.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	s := &Postgres{pool: pool, owned: true}
	if err := s.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// NewPostgres wraps an existing pool, for a process that already has one.
func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

// Migrate applies the schema.
func (s *Postgres) Migrate(ctx context.Context) error {
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, string(schema)); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

func (s *Postgres) SaveEvaluation(ctx context.Context, e Evaluation) error {
	event, err := json.Marshal(e.Event)
	if err != nil {
		return err
	}
	results, err := json.Marshal(e.Results)
	if err != nil {
		return err
	}
	decision, err := json.Marshal(e.Decision)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		insert into cerberus.evaluations
			(event_id, agent, session_id, kind, received_at, decided_at, action, severity,
			 flagged, masked, latency_ms, workflow_id, event, results, decision)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		on conflict (event_id) do update set
			decided_at = excluded.decided_at,
			action     = excluded.action,
			severity   = excluded.severity,
			flagged    = excluded.flagged,
			masked     = excluded.masked,
			latency_ms = excluded.latency_ms,
			results    = excluded.results,
			decision   = excluded.decision`,
		e.EventID, e.Agent, nullable(e.SessionID), string(e.Kind), e.ReceivedAt.UTC(), e.DecidedAt.UTC(),
		string(e.Decision.Action), string(e.Decision.Severity), len(e.Decision.Violations) > 0,
		e.Masked, float64(e.Latency)/float64(time.Millisecond), nullable(e.WorkflowID),
		event, results, decision)
	if err != nil {
		return fmt.Errorf("store: save evaluation %s: %w", e.EventID, err)
	}
	return nil
}

func (s *Postgres) Evaluation(ctx context.Context, eventID string) (Evaluation, error) {
	row := s.pool.QueryRow(ctx, `
		select event_id, agent, coalesce(session_id,''), kind, received_at, decided_at,
		       masked, latency_ms, coalesce(workflow_id,''), event, results, decision
		from cerberus.evaluations where event_id = $1`, eventID)
	e, err := scanEvaluation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Evaluation{}, fmt.Errorf("%w: event %s", ErrNotFound, eventID)
	}
	return e, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanEvaluation(row scanner) (Evaluation, error) {
	var (
		e         Evaluation
		kind      string
		latencyMS float64
		event     []byte
		results   []byte
		decision  []byte
	)
	if err := row.Scan(&e.EventID, &e.Agent, &e.SessionID, &kind, &e.ReceivedAt, &e.DecidedAt,
		&e.Masked, &latencyMS, &e.WorkflowID, &event, &results, &decision); err != nil {
		return Evaluation{}, err
	}
	e.Kind = core.Kind(kind)
	e.Latency = time.Duration(latencyMS * float64(time.Millisecond))
	if err := json.Unmarshal(event, &e.Event); err != nil {
		return Evaluation{}, err
	}
	if err := json.Unmarshal(results, &e.Results); err != nil {
		return Evaluation{}, err
	}
	if err := json.Unmarshal(decision, &e.Decision); err != nil {
		return Evaluation{}, err
	}
	return e, nil
}

func (s *Postgres) ListEvaluations(ctx context.Context, f EventFilter) ([]Evaluation, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		select event_id, agent, coalesce(session_id,''), kind, received_at, decided_at,
		       masked, latency_ms, coalesce(workflow_id,''), event, results, decision
		from cerberus.evaluations
		where ($1 = '' or agent = $1)
		  and ($2::timestamptz is null or received_at >= $2)
		  and (not $3 or flagged)
		order by received_at desc
		limit $4`,
		f.Agent, nullableTime(f.Since), f.FlaggedOnly, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evaluation
	for rows.Next() {
		e, err := scanEvaluation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Postgres) EnqueueReview(ctx context.Context, r Review) error {
	violations, err := json.Marshal(r.Violations)
	if err != nil {
		return err
	}
	event, err := json.Marshal(r.Event)
	if err != nil {
		return err
	}
	// do nothing on conflict: a replayed workflow re-runs this insert with the
	// same deterministic id and must not create a second queue item.
	_, err = s.pool.Exec(ctx, `
		insert into cerberus.reviews (id, event_id, agent, action, severity, state, created_at, violations, event)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		on conflict (id) do nothing`,
		r.ID, r.EventID, r.Agent, string(r.Action), string(r.Severity), string(ReviewPending),
		r.CreatedAt.UTC(), violations, event)
	if err != nil {
		return fmt.Errorf("store: enqueue review %s: %w", r.ID, err)
	}
	return nil
}

const reviewColumns = `id, event_id, agent, action, severity, state, created_at, decided_at,
	coalesce(reviewer,''), coalesce(notes,''), violations, labels, event`

func scanReview(row scanner) (Review, error) {
	var (
		r          Review
		action     string
		severity   string
		state      string
		decidedAt  *time.Time
		violations []byte
		labels     []byte
		event      []byte
	)
	if err := row.Scan(&r.ID, &r.EventID, &r.Agent, &action, &severity, &state, &r.CreatedAt,
		&decidedAt, &r.Reviewer, &r.Notes, &violations, &labels, &event); err != nil {
		return Review{}, err
	}
	r.Action = policy.Action(action)
	r.Severity = policy.Severity(severity)
	r.State = ReviewState(state)
	r.DecidedAt = decidedAt
	if err := json.Unmarshal(violations, &r.Violations); err != nil {
		return Review{}, err
	}
	if err := json.Unmarshal(labels, &r.Labels); err != nil {
		return Review{}, err
	}
	if err := json.Unmarshal(event, &r.Event); err != nil {
		return Review{}, err
	}
	return r, nil
}

func (s *Postgres) Review(ctx context.Context, id string) (Review, error) {
	row := s.pool.QueryRow(ctx, `select `+reviewColumns+` from cerberus.reviews where id = $1`, id)
	r, err := scanReview(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Review{}, fmt.Errorf("%w: review %s", ErrNotFound, id)
	}
	return r, err
}

func (s *Postgres) ListReviews(ctx context.Context, f ReviewFilter) ([]Review, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		select `+reviewColumns+`
		from cerberus.reviews
		where ($1 = '' or agent = $1) and ($2 = '' or state = $2)
		order by case severity
			when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end desc,
			created_at asc
		limit $3`, f.Agent, string(f.State), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Review
	for rows.Next() {
		r, err := scanReview(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Postgres) DecideReview(ctx context.Context, id string, d ReviewDecision) (Review, error) {
	labels, err := json.Marshal(d.Labels)
	if err != nil {
		return Review{}, err
	}
	// The pending predicate is in the UPDATE, so two reviewers racing on the
	// same item cannot both record a decision.
	row := s.pool.QueryRow(ctx, `
		update cerberus.reviews
		set state = $2, reviewer = $3, notes = $4, labels = $5, decided_at = now()
		where id = $1 and state = 'pending'
		returning `+reviewColumns,
		id, string(d.State), d.Reviewer, d.Notes, labels)
	r, err := scanReview(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if existing, lookupErr := s.Review(ctx, id); lookupErr == nil {
			return Review{}, fmt.Errorf("store: review %s is already %s", id, existing.State)
		}
		return Review{}, fmt.Errorf("%w: review %s", ErrNotFound, id)
	}
	return r, err
}

func (s *Postgres) AdvanceSession(ctx context.Context, ev core.Event) (core.SessionState, error) {
	if ev.SessionID == "" {
		return ev.Session, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.SessionState{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		state core.SessionState
		calls []byte
	)
	err = tx.QueryRow(ctx, `
		select started_at, turn_count, tokens_spent, cost_usd, recent_calls
		from cerberus.sessions where agent = $1 and session_id = $2 for update`,
		ev.AgentID, ev.SessionID).Scan(&state.StartedAt, &state.TurnCount, &state.TokensSpent, &state.CostSpentUSD, &calls)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// first event of the session
	case err != nil:
		return core.SessionState{}, err
	default:
		if err := json.Unmarshal(calls, &state.RecentCalls); err != nil {
			return core.SessionState{}, err
		}
	}

	stored, visible := fold(state, ev)
	encoded, err := json.Marshal(stored.RecentCalls)
	if err != nil {
		return core.SessionState{}, err
	}
	if _, err := tx.Exec(ctx, `
		insert into cerberus.sessions (agent, session_id, started_at, turn_count, tokens_spent, cost_usd, recent_calls, updated_at)
		values ($1,$2,$3,$4,$5,$6,$7, now())
		on conflict (agent, session_id) do update set
			turn_count = excluded.turn_count,
			tokens_spent = excluded.tokens_spent,
			cost_usd = excluded.cost_usd,
			recent_calls = excluded.recent_calls,
			updated_at = now()`,
		ev.AgentID, ev.SessionID, stored.StartedAt.UTC(), stored.TurnCount, stored.TokensSpent,
		stored.CostSpentUSD, encoded); err != nil {
		return core.SessionState{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.SessionState{}, err
	}
	return visible, nil
}

func (s *Postgres) LabelStats(ctx context.Context, since time.Time) ([]LabelStats, error) {
	rows, err := s.pool.Query(ctx, `
		select label->>'check' as check_name,
		       coalesce(label->>'check_version','') as check_version,
		       count(*) filter (where label->>'label' = 'true_positive')  as tp,
		       count(*) filter (where label->>'label' = 'false_positive') as fp,
		       count(*) filter (where label->>'label' = 'unsure')         as unsure
		from cerberus.reviews r, jsonb_array_elements(r.labels) as label
		where r.decided_at is not null and ($1::timestamptz is null or r.decided_at >= $1)
		group by 1, 2
		order by 1, 2`, nullableTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabelStats
	for rows.Next() {
		var st LabelStats
		if err := rows.Scan(&st.Check, &st.Version, &st.TruePositives, &st.FalsePositives, &st.Unsure); err != nil {
			return nil, err
		}
		if n := st.TruePositives + st.FalsePositives; n > 0 {
			st.Precision = float64(st.TruePositives) / float64(n)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Pool exposes the connection pool so the engine can hand the same database to
// anchora instead of opening a second one.
func (s *Postgres) Pool() *pgxpool.Pool { return s.pool }

func (s *Postgres) Close() error {
	if s.owned {
		s.pool.Close()
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
