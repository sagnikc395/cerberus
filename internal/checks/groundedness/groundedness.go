// Package groundedness checks whether a completion is supported by the context
// the agent was given. It is the one check that can reach a model, so it runs
// in the LLM-judge tier, on a sample of traffic, behind a cheap pre-filter.
//
// Status: experimental. The accuracy of the judge is not yet measured on a
// labeled set, so policies should route its verdicts to review rather than to
// a blocking action. See docs/failure-modes.md.
package groundedness

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
)

// Judge answers whether a claim is supported by the supplied context. An
// implementation may call a model; the heuristic judge does not.
type Judge interface {
	// Judge returns the probability that the completion is unsupported, a
	// short rationale, and what the call cost in USD.
	Judge(ctx context.Context, completion string, documents []core.Document) (score float64, rationale string, costUSD float64, err error)
}

// Check samples completions and asks a judge whether they are grounded in the
// context the agent retrieved.
type Check struct {
	// Judge is the backend. Nil means the heuristic overlap judge.
	Judge Judge
	// SampleRate is the fraction of applicable events judged, 0..1. Sampling is
	// deterministic in the event id, so a replay of the same traffic judges the
	// same events and a dry run is comparable with the original run.
	SampleRate float64
	// MinOverlapToSkip is the lexical-overlap level above which an event is
	// treated as grounded without asking the judge. This is the pre-filter that
	// keeps the expensive tier rare.
	MinOverlapToSkip float64
	Timeout          time.Duration
	Ver              string
}

// New returns the groundedness check with the heuristic judge.
func New() *Check {
	return &Check{
		SampleRate:       0.05,
		MinOverlapToSkip: 0.8,
		Timeout:          10 * time.Second,
		Ver:              "0.1.0-experimental",
	}
}

func (c *Check) Name() string    { return "groundedness" }
func (c *Check) Version() string { return c.Ver }
func (c *Check) Tier() core.Tier { return core.TierLLMJudge }

// AppliesTo requires a completion and something to ground it in.
func (c *Check) AppliesTo(ev core.Event) bool {
	return ev.Completion != "" && len(ev.Context) > 0 && c.sampled(ev)
}

// RunsIndependently keeps the check in play when the cheap tiers are clean: an
// ungrounded answer usually looks perfectly benign to a regex. Its cost is
// bounded by SampleRate and by the overlap pre-filter instead.
func (c *Check) RunsIndependently() bool { return true }

// Configure reads {"sample_rate": 0.1, "min_overlap_to_skip": 0.7}.
func (c *Check) Configure(params map[string]any) error {
	if v, ok := params["sample_rate"].(float64); ok {
		if v < 0 || v > 1 {
			return fmt.Errorf("groundedness: sample_rate must be between 0 and 1")
		}
		c.SampleRate = v
	}
	if v, ok := params["min_overlap_to_skip"].(float64); ok {
		c.MinOverlapToSkip = v
	}
	return nil
}

// sampled decides whether this event is in the judged sample. Hashing the
// event id keeps the decision stable across processes and replays.
func (c *Check) sampled(ev core.Event) bool {
	if c.SampleRate >= 1 {
		return true
	}
	if c.SampleRate <= 0 {
		return false
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(ev.ID))
	return float64(h.Sum64()%10_000)/10_000 < c.SampleRate
}

func (c *Check) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	v := core.Verdict{Label: core.LabelOK}

	if overlap := Overlap(ev.Completion, ev.Context); overlap >= c.MinOverlapToSkip {
		v.Latency = time.Since(start)
		return v, nil
	}
	judge := c.Judge
	if judge == nil {
		judge = heuristicJudge{}
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	score, rationale, cost, err := judge.Judge(ctx, ev.Completion, ev.Context)
	v.Latency = time.Since(start)
	v.CostUSD = cost
	if err != nil {
		return v, fmt.Errorf("groundedness: judge: %w", err)
	}
	v.Score = score
	if score >= 0.5 {
		v.Label = "ungrounded"
		v.Evidence = []core.Span{{
			Field: core.FieldCompletion,
			Start: 0,
			End:   len(ev.Completion),
			Text:  clip(ev.Completion, 240),
			Note:  rationale,
		}}
	}
	return v, nil
}

// heuristicJudge scores on lexical overlap alone. It exists so the check runs
// with no provider configured, and so the eval harness has a baseline to beat.
type heuristicJudge struct{}

func (heuristicJudge) Judge(_ context.Context, completion string, docs []core.Document) (float64, string, float64, error) {
	overlap := Overlap(completion, docs)
	score := 1 - overlap
	return score, fmt.Sprintf("heuristic: %.0f%% of content words in the completion appear in the context", overlap*100), 0, nil
}

var wordRe = regexp.MustCompile(`[\p{L}\p{N}][\p{L}\p{N}'\-]*`)

// Overlap is the share of the completion's content words that appear in the
// context. It is a weak signal on its own, which is why it is only used as a
// pre-filter and as the baseline judge.
func Overlap(completion string, docs []core.Document) float64 {
	words := contentWords(completion)
	if len(words) == 0 {
		return 1
	}
	var corpus strings.Builder
	for _, d := range docs {
		corpus.WriteString(strings.ToLower(d.Content))
		corpus.WriteByte(' ')
	}
	haystack := corpus.String()
	hits := 0
	for w := range words {
		if strings.Contains(haystack, w) {
			hits++
		}
	}
	return math.Round(float64(hits)/float64(len(words))*1000) / 1000
}

func contentWords(s string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
		if len(w) < 4 || stopwords[w] {
			continue
		}
		out[w] = struct{}{}
	}
	return out
}

var stopwords = map[string]bool{
	"that": true, "this": true, "with": true, "from": true, "your": true,
	"have": true, "will": true, "they": true, "them": true, "then": true,
	"than": true, "been": true, "were": true, "what": true, "when": true,
	"which": true, "there": true, "their": true, "about": true, "would": true,
	"could": true, "should": true, "please": true, "thanks": true,
}

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
