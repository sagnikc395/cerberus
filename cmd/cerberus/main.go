// Command cerberus runs the control plane: the ingest API, the evaluation
// workers, the review API, and the metrics endpoint. One process runs all of
// them; several processes pointed at the same database share the work through
// anchora's leases.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sagnikc395/anchora/anchora"
	anchoramem "github.com/sagnikc395/anchora/anchora/memory"

	"github.com/sagnikc395/cerberus/internal/api"
	"github.com/sagnikc395/cerberus/internal/broker"
	"github.com/sagnikc395/cerberus/internal/checks/groundedness"
	"github.com/sagnikc395/cerberus/internal/engine"
	"github.com/sagnikc395/cerberus/internal/metrics"
	"github.com/sagnikc395/cerberus/internal/policy"
	"github.com/sagnikc395/cerberus/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("cerberus: %v", err)
	}
}

func run() error {
	var (
		addr          = flag.String("addr", env("CERBERUS_ADDR", ":8080"), "address the HTTP API listens on")
		databaseURL   = flag.String("database-url", os.Getenv("DATABASE_URL"), "Postgres URL; empty runs in memory (no durability)")
		natsURL       = flag.String("nats-url", os.Getenv("NATS_URL"), "NATS URL; empty submits directly to Anchora")
		policyDir     = flag.String("policies", env("CERBERUS_POLICY_DIR", "policies"), "directory of policy files")
		token         = flag.String("token", os.Getenv("CERBERUS_TOKEN"), "bearer token required on /v1 routes; empty disables auth")
		reviewTimeout = flag.String("review-timeout", env("CERBERUS_REVIEW_TIMEOUT", "24h"), "how long a parked event waits for a reviewer")
		refresh       = flag.Duration("refresh", 15*time.Second, "how often queue depth and reviewer precision gauges are refreshed")
	)
	flag.Parse()
	if *refresh <= 0 {
		return errors.New("refresh must be positive")
	}

	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)
	logf := func(format string, args ...any) { logger.Printf(format, args...) }

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	policies, err := policy.LoadDir(*policyDir)
	if err != nil {
		return err
	}
	logf("loaded policies for %s", strings.Join(policies.Agents(), ", "))

	reviewWait, err := time.ParseDuration(*reviewTimeout)
	if err != nil {
		return fmt.Errorf("review-timeout: %w", err)
	}

	m := metrics.Default()

	// Store and durable-execution state share one Postgres. Without a database
	// URL the process runs entirely in memory, which is what `make demo` and
	// the tests use: same code paths, nothing survives a restart.
	var (
		dataStore  store.Store
		anchoraCfg anchora.Config
	)
	if *databaseURL != "" {
		pg, err := store.OpenPostgres(ctx, *databaseURL)
		if err != nil {
			return err
		}
		defer pg.Close()
		dataStore = pg
		anchoraCfg = anchora.Config{DatabaseURL: *databaseURL}
		logf("store: postgres")
	} else {
		dataStore = store.NewMemory()
		anchoraCfg = anchora.Config{Store: anchoramem.New()}
		logf("store: memory (no durability; set DATABASE_URL for a real deployment)")
	}
	anchoraCfg.AppVersion = appVersion()
	anchoraCfg.Logf = func(format string, args ...any) { logf("anchora: "+format, args...) }

	durable, err := anchora.New(ctx, anchoraCfg)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := durable.Shutdown(shutdownCtx); err != nil {
			logf("anchora shutdown: %v", err)
		}
	}()

	registry := engine.DefaultRegistry()
	// The groundedness judge is opt-in: with no credentials the check falls
	// back to its heuristic baseline rather than failing or going silent.
	if judge, ok := groundedness.NewClaudeJudge(); ok {
		g := groundedness.New()
		g.Judge = judge
		g.Ver = g.Ver + "+claude"
		if err := registry.Register(g); err != nil {
			return err
		}
		logf("groundedness: llm judge enabled")
	} else {
		logf("groundedness: heuristic judge (set ANTHROPIC_API_KEY for the llm judge)")
	}

	eng, err := engine.New(engine.Config{
		Anchora:       durable,
		Store:         dataStore,
		Policies:      policies,
		Registry:      registry,
		Metrics:       m,
		ReviewTimeout: reviewWait,
		Logf:          logf,
	})
	if err != nil {
		return err
	}
	if err := durable.Launch(); err != nil {
		return err
	}

	var bus broker.Broker
	if *natsURL != "" {
		nb, err := broker.NewNATS(ctx, *natsURL, "engine")
		if err != nil {
			return err
		}
		bus = nb
		logf("broker: nats jetstream at %s", *natsURL)
		defer bus.Close()
		if err := bus.Subscribe(ctx, eng.Handler()); err != nil {
			return err
		}
	}

	srv := &http.Server{
		Addr: *addr,
		Handler: api.New(api.Config{
			Engine:   eng,
			Broker:   bus,
			Store:    dataStore,
			Policies: policies,
			Registry: registry,
			Metrics:  m,
			Token:    *token,
			Logf:     logf,
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go refreshGauges(ctx, *refresh, bus, dataStore, m, logf)

	errs := make(chan error, 1)
	go func() {
		logf("listening on %s", *addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		logf("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// refreshGauges keeps the gauges that are not event-driven current: broker
// depth and lag, review queue depth, and the reviewer-confirmed precision the
// dashboard shows next to each check.
func refreshGauges(ctx context.Context, every time.Duration, bus broker.Broker, s store.Store, m *metrics.Metrics, logf func(string, ...any)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if bus != nil {
			if depth, err := bus.Depth(ctx); err == nil && depth >= 0 {
				m.QueueDepth.WithLabelValues(broker.Subject).Set(float64(depth))
			}
		}
		pending, err := s.ListReviews(ctx, store.ReviewFilter{State: store.ReviewPending, Limit: 10_000})
		if err != nil {
			logf("refresh reviews: %v", err)
			continue
		}
		byAgent := map[string]float64{}
		oldest := time.Time{}
		for _, r := range pending {
			byAgent[r.Agent]++
			if oldest.IsZero() || r.CreatedAt.Before(oldest) {
				oldest = r.CreatedAt
			}
		}
		m.ReviewDepth.Reset()
		for agent, n := range byAgent {
			m.ReviewDepth.WithLabelValues(agent).Set(n)
		}
		if oldest.IsZero() {
			m.QueueLag.Set(0)
		} else {
			m.QueueLag.Set(time.Since(oldest).Seconds())
		}
		stats, err := s.LabelStats(ctx, time.Time{})
		if err != nil {
			logf("refresh precision: %v", err)
			continue
		}
		for _, st := range stats {
			if st.TruePositives+st.FalsePositives == 0 {
				continue
			}
			m.ReviewerPrecision.WithLabelValues(st.Check, st.Version).Set(st.Precision)
		}
	}
}

// appVersion gates anchora's recovery: an executor only recovers workflows it
// can run. It is set from the build so two deployments with different check
// code do not claim each other's in-flight evaluations.
func appVersion() string {
	if v := os.Getenv("CERBERUS_APP_VERSION"); v != "" {
		return v
	}
	return "cerberus-dev"
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
