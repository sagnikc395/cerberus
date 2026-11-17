// Package secrets detects credentials in outbound text: provider-specific key
// shapes, PEM blocks, bearer tokens, and generic assignments whose value is
// random enough to be a key rather than a word.
package secrets

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/sagnikc395/cerberus/internal/core"
)

type rule struct {
	name    string
	re      *regexp.Regexp
	score   float64
	group   int     // submatch holding the value, 0 for the whole match
	entropy float64 // minimum bits per character the value must carry, 0 to skip
}

var rules = []rule{
	{name: "aws_access_key_id", score: 0.95, re: regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`), group: 1},
	{name: "aws_secret_access_key", score: 0.95, entropy: 3.5, re: regexp.MustCompile(`(?i)aws[^\n]{0,24}?\b([A-Za-z0-9/+=]{40})\b`), group: 1},
	{name: "github_token", score: 0.95, re: regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b`), group: 1},
	{name: "slack_token", score: 0.95, re: regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b`), group: 1},
	{name: "google_api_key", score: 0.9, re: regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), group: 1},
	{name: "stripe_secret_key", score: 0.95, re: regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b`), group: 1},
	{name: "openai_style_key", score: 0.9, re: regexp.MustCompile(`\b(sk-[A-Za-z0-9_\-]{20,})\b`), group: 1},
	{name: "anthropic_style_key", score: 0.9, re: regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_\-]{20,})\b`), group: 1},
	{name: "private_key_block", score: 0.99, re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`)},
	{name: "jwt", score: 0.7, re: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`), group: 1},
	{name: "bearer_token", score: 0.75, entropy: 3.0, re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9_\-.=]{20,})`), group: 1},
	{name: "postgres_url", score: 0.9, re: regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s:@/]+@[^\s/]+`)},
	{name: "generic_assigned_secret", score: 0.6, entropy: 3.2, re: regexp.MustCompile(`(?i)\b(?:api[_\-]?key|secret|token|passwd|password|access[_\-]?key|client[_\-]?secret)\b\s*[:=]\s*["']?([A-Za-z0-9_\-+/=]{20,})["']?`), group: 1},
}

// Match is one credential found in text.
type Match struct {
	Rule  string
	Score float64
	Start int
	End   int
	Value string
}

// Mask keeps a credential identifiable without storing it: the rule that found
// it, its length, and four trailing characters.
func Mask(m Match) string {
	tail := m.Value
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return m.Rule + " (" + itoa(len(m.Value)) + " chars, ends …" + tail + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Scan returns every credential in text.
func Scan(text string) []Match {
	if text == "" {
		return nil
	}
	var out []Match
	for _, r := range rules {
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := loc[0], loc[1]
			value := text[start:end]
			if r.group > 0 && len(loc) > 2*r.group+1 && loc[2*r.group] >= 0 {
				start, end = loc[2*r.group], loc[2*r.group+1]
				value = text[start:end]
			}
			if r.entropy > 0 && shannon(value) < r.entropy {
				continue
			}
			if looksLikePlaceholder(value) {
				continue
			}
			out = append(out, Match{Rule: r.name, Score: r.score, Start: start, End: end, Value: value})
		}
	}
	return out
}

// looksLikePlaceholder drops the documentation strings that otherwise dominate
// the false positives: YOUR_API_KEY, xxxxxxxx, <token>, ${SECRET}.
func looksLikePlaceholder(v string) bool {
	lower := strings.ToLower(v)
	for _, s := range []string{"your_", "yourkey", "example", "placeholder", "redacted", "changeme", "xxxx", "dummy", "test_key", "<", "${"} {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// shannon is the per-character entropy of a value in bits. A word has roughly
// 2.5 bits per character; a random 40-char key has close to 6.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}

// LeakCheck is the outbound credential guardrail. It reads the completion and
// the tool arguments: a secret pasted into a tool call leaves the system just
// as surely as one printed to the user.
type LeakCheck struct {
	Ver string
}

// NewLeakCheck returns the secret-leakage check.
func NewLeakCheck() *LeakCheck { return &LeakCheck{Ver: "1.0.0"} }

func (c *LeakCheck) Name() string    { return "secret_leak" }
func (c *LeakCheck) Version() string { return c.Ver }
func (c *LeakCheck) Tier() core.Tier { return core.TierRegex }

func (c *LeakCheck) AppliesTo(ev core.Event) bool {
	return ev.Completion != "" || ev.ToolCall != nil
}

func (c *LeakCheck) Run(ctx context.Context, ev core.Event) (core.Verdict, error) {
	start := time.Now()
	v := core.Verdict{Label: core.LabelOK}
	for _, f := range []core.Field{core.FieldCompletion, core.FieldToolArgs} {
		text := ev.Text(f, 0)
		for _, m := range Scan(text) {
			v.Label = "secret_leak"
			if m.Score > v.Score {
				v.Score = m.Score
			}
			v.Evidence = append(v.Evidence, core.Span{
				Field: f,
				Start: m.Start,
				End:   m.End,
				Text:  Mask(m),
				Note:  m.Rule,
			})
		}
	}
	v.Latency = time.Since(start)
	return v, nil
}
