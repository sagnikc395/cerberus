// Package redact removes personal data and credentials from an event before it
// is persisted. Replacements keep the byte length of what they replace, so the
// evidence spans a check produced still point at the right place in the stored
// text and a reviewer sees the span highlighted over the mask.
package redact

import (
	"sort"
	"strings"

	"github.com/sagnikc395/cerberus/internal/checks/pii"
	"github.com/sagnikc395/cerberus/internal/checks/secrets"
	"github.com/sagnikc395/cerberus/internal/core"
)

type span struct {
	start, end int
	label      string
}

// Text returns text with every detected value masked, and the number of
// values masked.
func Text(text string) (string, int) {
	if text == "" {
		return text, 0
	}
	var spans []span
	for _, m := range pii.Scan(text) {
		spans = append(spans, span{start: m.Start, end: m.End, label: string(m.Type)})
	}
	for _, m := range secrets.Scan(text) {
		spans = append(spans, span{start: m.Start, end: m.End, label: m.Rule})
	}
	if len(spans) == 0 {
		return text, 0
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	var b strings.Builder
	b.Grow(len(text))
	cursor, masked := 0, 0
	for i := 0; i < len(spans); {
		s := spans[i]
		i++
		for i < len(spans) && spans[i].start < s.end {
			s.end = max(s.end, spans[i].end)
			i++
		}
		b.WriteString(text[cursor:s.start])
		b.WriteString(mask(s.label, s.end-s.start))
		cursor = s.end
		masked++
	}

	b.WriteString(text[cursor:])
	return b.String(), masked
}

// mask renders a label inside exactly n bytes, so offsets survive redaction.
func mask(label string, n int) string {
	if n <= 0 {
		return ""
	}
	tag := "[" + label + "]"
	switch {
	case len(tag) == n:
		return tag
	case len(tag) < n:
		return tag + strings.Repeat("*", n-len(tag))
	case n >= 3:
		return "[" + strings.Repeat("*", n-2) + "]"
	default:
		return strings.Repeat("*", n)
	}
}

// Event masks detected sensitive values in event content and returns a copy
// for evaluation and review records.
func Event(ev core.Event) (core.Event, int) {
	total := 0
	out := ev

	redact := func(text string) string {
		value, n := Text(text)
		total += n
		return value
	}
	out.Prompt = redact(ev.Prompt)
	out.Completion = redact(ev.Completion)
	out.Context = append([]core.Document(nil), ev.Context...)
	for i := range out.Context {
		out.Context[i].Source = redact(out.Context[i].Source)
		out.Context[i].Content = redact(out.Context[i].Content)
	}
	if ev.Metadata != nil {
		out.Metadata = make(map[string]string, len(ev.Metadata))
		for key, value := range ev.Metadata {
			out.Metadata[key] = redact(value)
		}
	}
	if ev.ToolCall != nil {
		call := *ev.ToolCall
		call.Args = redactArgs(call.Args, redact)
		out.ToolCall = &call
	}
	out.Session.RecentCalls = append([]core.ToolCall(nil), ev.Session.RecentCalls...)
	for i := range out.Session.RecentCalls {
		call := &out.Session.RecentCalls[i]
		call.Args = redactArgs(call.Args, redact)
	}
	return out, total
}

func redactValue(value any, redact func(string) string) any {
	switch v := value.(type) {
	case string:
		return redact(v)
	case map[string]any:
		return redactArgs(v, redact)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactValue(item, redact)
		}
		return out
	default:
		return value
	}
}

// Results redacts the evidence text a check attached to its verdict. Checks
// already mask the values they report, but a span's Text is free-form, so it
// is swept again on the way to the store.
func Results(results []core.Result) []core.Result {
	out := make([]core.Result, len(results))
	copy(out, results)
	for i := range out {
		if len(out[i].Verdict.Evidence) == 0 {
			continue
		}
		spans := make([]core.Span, len(out[i].Verdict.Evidence))
		copy(spans, out[i].Verdict.Evidence)
		for j := range spans {
			spans[j].Text, _ = Text(spans[j].Text)
			spans[j].Note, _ = Text(spans[j].Note)
		}
		out[i].Verdict.Evidence = spans
	}
	return out
}

func redactArgs(args map[string]any, redact func(string) string) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for key, item := range args {
		out[key] = redactValue(item, redact)
	}
	return out
}
