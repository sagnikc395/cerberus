// Package api is the control plane's HTTP surface: ingest for agents and SDKs,
// the review queue for humans, and read-only views of policies, checks and
// measured accuracy.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sagnikc395/cerberus/internal/broker"
	"github.com/sagnikc395/cerberus/internal/core"
	"github.com/sagnikc395/cerberus/internal/engine"
	"github.com/sagnikc395/cerberus/internal/metrics"
	"github.com/sagnikc395/cerberus/internal/policy"
	"github.com/sagnikc395/cerberus/internal/store"
)

// MaxBodyBytes bounds one ingest request. An agent that wants to send more
// than this is sending a transcript, not an event.
const MaxBodyBytes = 1 << 20

// Config wires the server.
type Config struct {
	Engine   *engine.Engine
	Broker   broker.Broker
	Store    store.Store
	Policies *policy.Set
	Registry *core.Registry
	Metrics  *metrics.Metrics
	// Token, when set, is required as a bearer token on every /v1 route.
	// Per-tenant authentication is explicitly out of scope; this is the shared
	// secret that keeps the ingest endpoint off the open internet.
	Token string
	Logf  func(format string, args ...any)
}

// Server is the HTTP handler set.
type Server struct {
	cfg Config
	mux *http.ServeMux
}

// New builds the server and its routes.
func New(cfg Config) *Server {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}

	s.mux.HandleFunc("POST /v1/events", s.auth(s.ingest))
	s.mux.HandleFunc("GET /v1/events", s.auth(s.listEvents))
	s.mux.HandleFunc("GET /v1/events/{id}", s.auth(s.getEvent))
	s.mux.HandleFunc("GET /v1/reviews", s.auth(s.listReviews))
	s.mux.HandleFunc("GET /v1/reviews/{id}", s.auth(s.getReview))
	s.mux.HandleFunc("POST /v1/reviews/{id}/decision", s.auth(s.decideReview))
	s.mux.HandleFunc("GET /v1/policies", s.auth(s.listPolicies))
	s.mux.HandleFunc("GET /v1/policies/{agent}", s.auth(s.getPolicy))
	s.mux.HandleFunc("GET /v1/checks", s.auth(s.listChecks))
	s.mux.HandleFunc("GET /v1/stats/precision", s.auth(s.labelStats))

	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /readyz", s.ready)
	s.mux.Handle("GET /metrics", promhttp.Handler())
	return s
}

// Handler returns the router.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") || header[len("Bearer "):] != s.cfg.Token {
				writeError(w, http.StatusUnauthorized, "invalid or missing bearer token")
				return
			}
		}
		next(w, r)
	}
}

// ingestRequest is the SDK's payload. It is the event plus the one thing an
// agent cannot decide for itself: whether it wants to wait for the verdict.
type ingestRequest struct {
	core.Event
	// Wait asks for synchronous evaluation: the response carries the action,
	// which is what an agent does when it intends to honour a block.
	Wait bool `json:"wait,omitempty"`
}

type ingestResponse struct {
	EventID  string          `json:"event_id"`
	Accepted bool            `json:"accepted"`
	Outcome  *engine.Outcome `json:"outcome,omitempty"`
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	var req ingestRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.rejected("malformed_json")
		writeError(w, http.StatusBadRequest, "malformed event: "+err.Error())
		return
	}
	if dec.Decode(new(json.RawMessage)) != io.EOF {
		s.rejected("malformed_json")
		writeError(w, http.StatusBadRequest, "expected one JSON event")
		return
	}
	ev, err := normalize(req.Event)
	if err != nil {
		s.rejected("invalid_event")
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.EventsReceived.WithLabelValues(ev.AgentID, string(ev.Kind)).Inc()
	}

	if req.Wait {
		// The agent is holding its turn for the verdict, so evaluation runs on
		// this request rather than through the broker.
		outcome, err := s.cfg.Engine.AwaitDecision(r.Context(), ev)
		if err != nil {
			s.cfg.Logf("evaluate %s: %v", ev.ID, err)
			writeError(w, http.StatusInternalServerError, "evaluation failed")
			return
		}
		writeJSON(w, http.StatusOK, ingestResponse{EventID: ev.ID, Accepted: true, Outcome: &outcome})
		return
	}
	if err := s.submit(r.Context(), ev); err != nil {
		s.rejected("submit_unavailable")
		s.cfg.Logf("publish %s: %v", ev.ID, err)
		writeError(w, http.StatusServiceUnavailable, "event submission unavailable")
		return
	}
	writeJSON(w, http.StatusAccepted, ingestResponse{EventID: ev.ID, Accepted: true})
}

func (s *Server) submit(ctx context.Context, ev core.Event) error {
	if s.cfg.Broker != nil {
		return s.cfg.Broker.Publish(ctx, ev)
	}
	_, err := s.cfg.Engine.Start(ctx, ev)
	return err
}

// normalize validates an incoming event and fills in what the agent left out.
// The id is derived from the content when it is absent, so a retry without an
// id is still idempotent.
func normalize(ev core.Event) (core.Event, error) {
	if ev.AgentID == "" {
		return ev, errors.New("agent_id is required")
	}
	if ev.Kind == "" {
		return ev, errors.New("kind is required")
	}
	switch ev.Kind {
	case core.KindPrompt, core.KindCompletion, core.KindToolCall, core.KindToolResult:
	default:
		return ev, fmt.Errorf("unknown kind %q", ev.Kind)
	}
	if ev.Kind == core.KindToolCall && ev.ToolCall == nil {
		return ev, errors.New("a tool_call event needs a tool_call")
	}
	ev.Session = core.SessionState{}
	if ev.ID == "" {
		// JSON frames the fields and sorts map keys for a stable hash.
		payload, err := json.Marshal(ev)
		if err != nil {
			return ev, err
		}
		hash := sha256.Sum256(payload)
		ev.ID = "ev_" + hex.EncodeToString(hash[:12])
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	return ev, nil
}

func (s *Server) rejected(reason string) {
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.IngestErrors.WithLabelValues(reason).Inc()
	}
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	f := store.EventFilter{
		Agent:       r.URL.Query().Get("agent"),
		FlaggedOnly: r.URL.Query().Get("flagged") == "true",
		Limit:       intParam(r, "limit", 50),
	}
	if since := r.URL.Query().Get("since"); since != "" {
		d, err := core.ParseDuration(since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be a duration like 7d or 24h")
			return
		}
		f.Since = time.Now().Add(-d)
	}
	out, err := s.cfg.Store.ListEvaluations(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "count": len(out)})
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	e, err := s.cfg.Store.Evaluation(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) listReviews(w http.ResponseWriter, r *http.Request) {
	state := store.ReviewState(r.URL.Query().Get("state"))
	if state == "" {
		state = store.ReviewPending
	}
	if state == "all" {
		state = ""
	}
	out, err := s.cfg.Store.ListReviews(r.Context(), store.ReviewFilter{
		Agent: r.URL.Query().Get("agent"),
		State: state,
		Limit: intParam(r, "limit", 50),
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reviews": out, "count": len(out)})
}

func (s *Server) getReview(w http.ResponseWriter, r *http.Request) {
	rev, err := s.cfg.Store.Review(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rev)
}

func (s *Server) decideReview(w http.ResponseWriter, r *http.Request) {
	var d store.ReviewDecision
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes)).Decode(&d); err != nil {
		writeError(w, http.StatusBadRequest, "malformed decision: "+err.Error())
		return
	}
	switch d.State {
	case store.ReviewApproved, store.ReviewRejected:
	default:
		writeError(w, http.StatusBadRequest, "state must be approved or rejected")
		return
	}
	if d.Reviewer == "" {
		writeError(w, http.StatusBadRequest, "reviewer is required: a label with no author is not evidence")
		return
	}
	for _, l := range d.Labels {
		switch l.Label {
		case store.LabelTruePositive, store.LabelFalsePositive, store.LabelUnsure:
		default:
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown label %q", l.Label))
			return
		}
	}
	rev, err := s.cfg.Store.DecideReview(r.Context(), r.PathValue("id"), d)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rev)
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, agent := range s.cfg.Policies.Agents() {
		active, _ := s.cfg.Policies.Active(agent)
		entry := map[string]any{"agent": agent, "versions": s.cfg.Policies.Versions(agent)}
		if active != nil {
			entry["active_version"] = active.Version
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": out})
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	agent := r.PathValue("agent")
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "version must be an integer")
			return
		}
		p, ok := s.cfg.Policies.Version(agent, n)
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Sprintf("%s v%d is not loaded", agent, n))
			return
		}
		writeJSON(w, http.StatusOK, p)
		return
	}
	p, ok := s.cfg.Policies.Active(agent)
	if !ok {
		writeError(w, http.StatusNotFound, "no policy for "+agent)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// listChecks reports what is registered and, for an agent, what that agent
// actually runs after its policy has configured and disabled things.
func (s *Server) listChecks(w http.ResponseWriter, r *http.Request) {
	type checkInfo struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Tier    string `json:"tier"`
	}
	describe := func(checks []core.Check) []checkInfo {
		out := make([]checkInfo, 0, len(checks))
		for _, c := range checks {
			out = append(out, checkInfo{Name: c.Name(), Version: c.Version(), Tier: c.Tier().String()})
		}
		return out
	}
	if agent := r.URL.Query().Get("agent"); agent != "" {
		plan := s.cfg.Engine.Plan(agent)
		writeJSON(w, http.StatusOK, map[string]any{"agent": agent, "checks": describe(plan.Checks)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": describe(s.cfg.Registry.All())})
}

func (s *Server) labelStats(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if raw := r.URL.Query().Get("since"); raw != "" {
		d, err := core.ParseDuration(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be a duration")
			return
		}
		since = time.Now().Add(-d)
	}
	stats, err := s.cfg.Store.LabelStats(r.Context(), since)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": stats})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if s.cfg.Broker == nil {
		if _, err := s.cfg.Store.ListEvaluations(ctx, store.EventFilter{Limit: 1}); err != nil {
			writeError(w, http.StatusServiceUnavailable, "store unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	depth, err := s.cfg.Broker.Depth(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "broker_error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "broker_depth": depth})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.cfg.Logf("request failed: %v", err)
	writeError(w, http.StatusInternalServerError, err.Error())
}

func intParam(r *http.Request, name string, def int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
