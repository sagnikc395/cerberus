package core

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Tier orders checks by what they cost to run. The executor runs a whole tier
// before deciding whether the next one is worth it.
type Tier int

const (
	// TierRegex is pattern matching and validators: microseconds, no network.
	TierRegex Tier = iota + 1
	// TierClassifier is a local model: milliseconds, no provider call.
	TierClassifier
	// TierLLMJudge calls a model. Slow and metered, so it runs last and rarely.
	TierLLMJudge
)

func (t Tier) String() string {
	switch t {
	case TierRegex:
		return "regex"
	case TierClassifier:
		return "classifier"
	case TierLLMJudge:
		return "llm_judge"
	}
	return fmt.Sprintf("tier(%d)", int(t))
}

// LabelOK is the verdict label of a check that found nothing.
const LabelOK = "ok"

// Verdict is what a check returns: the label it assigned, how sure it is, the
// exact text that triggered it, and what the call cost.
type Verdict struct {
	Label    string        `json:"label"`
	Score    float64       `json:"score"`
	Evidence []Span        `json:"evidence,omitempty"`
	Latency  time.Duration `json:"latency"`
	CostUSD  float64       `json:"cost_usd,omitempty"`
}

// Flagged reports whether the verdict says something was found.
func (v Verdict) Flagged() bool { return v.Label != "" && v.Label != LabelOK }

// Check is the one interface every guardrail implements. A check is pure with
// respect to the event: same event, same verdict, so it can be replayed against
// historical traffic during a policy dry run and scored by the eval harness.
type Check interface {
	Name() string
	Version() string
	Tier() Tier
	Run(ctx context.Context, ev Event) (Verdict, error)
}

// Applicable is an optional interface. A check that only reads completions
// declares it, and the executor skips it on other events instead of paying for
// a call that cannot fire.
type Applicable interface {
	AppliesTo(ev Event) bool
}

// Independent is an optional interface for a check whose cost is already
// bounded by its own sampling. The executor runs it even when the cheap tiers
// found nothing, because a check that only runs after something else fires can
// never catch what the cheap tiers cannot see.
type Independent interface {
	RunsIndependently() bool
}

// Configurable is an optional interface for checks whose thresholds or
// allowlists come from a policy rule's params.
type Configurable interface {
	Configure(params map[string]any) error
}

// Result is a verdict with the check that produced it attached.
type Result struct {
	Check   string  `json:"check"`
	Version string  `json:"version"`
	Tier    Tier    `json:"tier"`
	Verdict Verdict `json:"verdict"`
	Err     string  `json:"error,omitempty"`
	Skipped bool    `json:"skipped,omitempty"`
}

// Registry holds checks by name and version, so a new detector runs side by
// side with the one it is meant to replace on the same traffic.
type Registry struct {
	byKey  map[string]Check
	latest map[string]Check
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byKey: map[string]Check{}, latest: map[string]Check{}}
}

func key(name, version string) string { return name + "@" + version }

// Register adds a check. Registering the same name and version twice is an
// error: two detectors claiming one identity would make eval numbers lie.
func (r *Registry) Register(c Check) error {
	if c.Name() == "" || c.Version() == "" {
		return fmt.Errorf("core: check needs a name and a version")
	}
	k := key(c.Name(), c.Version())
	if _, dup := r.byKey[k]; dup {
		return fmt.Errorf("core: check %s is already registered", k)
	}
	r.byKey[k] = c
	if prev, ok := r.latest[c.Name()]; !ok || c.Version() > prev.Version() {
		r.latest[c.Name()] = c
	}
	return nil
}

// MustRegister is Register for package-level wiring.
func (r *Registry) MustRegister(c Check) {
	if err := r.Register(c); err != nil {
		panic(err)
	}
}

// Get resolves a check reference. An empty or "latest" version returns the
// highest registered version of that name.
func (r *Registry) Get(name, version string) (Check, bool) {
	if version == "" || version == "latest" {
		c, ok := r.latest[name]
		return c, ok
	}
	c, ok := r.byKey[key(name, version)]
	return c, ok
}

// Resolve accepts "name" or "name@version".
func (r *Registry) Resolve(ref string) (Check, bool) {
	name, version, _ := strings.Cut(ref, "@")
	return r.Get(name, version)
}

// All returns every registered check, ordered by tier then name, so execution
// order is stable across processes.
func (r *Registry) All() []Check {
	out := make([]Check, 0, len(r.byKey))
	for _, c := range r.byKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tier() != out[j].Tier() {
			return out[i].Tier() < out[j].Tier()
		}
		if out[i].Name() != out[j].Name() {
			return out[i].Name() < out[j].Name()
		}
		return out[i].Version() < out[j].Version()
	})
	return out
}

// Names returns the distinct check names in the registry.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.latest))
	for n := range r.latest {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func encodeArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	return string(b)
}

// EncodeArgs renders tool arguments the way spans into FieldToolArgs are
// measured against.
func EncodeArgs(args map[string]any) string { return encodeArgs(args) }

// Cloneable is implemented by a check that wants to control how a per-agent
// copy of itself is made. Most checks do not: Clone below copies the struct.
type Cloneable interface {
	Clone() Check
}

// Clone returns an independent copy of a check, so one agent's policy params
// cannot change what another agent runs. A check that needs more than a
// shallow copy implements Cloneable.
func Clone(c Check) Check {
	if cl, ok := c.(Cloneable); ok {
		return cl.Clone()
	}
	v := reflect.ValueOf(c)
	if v.Kind() != reflect.Ptr || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		// A value-typed check holds no mutable state worth copying.
		return c
	}
	copied := reflect.New(v.Elem().Type())
	copied.Elem().Set(v.Elem())
	clone, ok := copied.Interface().(Check)
	if !ok {
		return c
	}
	return clone
}
