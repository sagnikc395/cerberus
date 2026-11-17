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
	for _, s := range spans {
		if s.start < cursor { // overlapping detections: the first one wins
			continue
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

// Event returns a copy of ev with every text field redacted, and the total
// number of values masked. The returned event is what the store and the
// review queue see; the original never leaves the evaluation workflow.
func Event(ev core.Event) (core.Event, int) {
	total := 0
	out := ev

	out.Prompt, total = addMask(ev.Prompt, total)
	out.Completion, total = addMask(ev.Completion, total)

	if len(ev.Context) > 0 {
		out.Context = make([]core.Document, len(ev.Context))
		copy(out.Context, ev.Context)
		for i := range out.Context {
			out.Context[i].Content, total = addMask(out.Context[i].Content, total)
		}
	}
	if ev.ToolCall != nil {
		call := *ev.ToolCall
		if len(ev.ToolCall.Args) > 0 {
			call.Args = make(map[string]any, len(ev.ToolCall.Args))
			for k, v := range ev.ToolCall.Args {
				if s, ok := v.(string); ok {
					redacted, n := Text(s)
					call.Args[k] = redacted
					total += n
					continue
				}
				call.Args[k] = v
			}
		}
		out.ToolCall = &call
	}
	if len(ev.Session.RecentCalls) > 0 {
		out.Session.RecentCalls = make([]core.ToolCall, len(ev.Session.RecentCalls))
		for i, call := range ev.Session.RecentCalls {
			redacted := call
			if len(call.Args) > 0 {
				redacted.Args = make(map[string]any, len(call.Args))
				for k, v := range call.Args {
					if s, ok := v.(string); ok {
						masked, n := Text(s)
						redacted.Args[k] = masked
						total += n
						continue
					}
					redacted.Args[k] = v
				}
			}
			out.Session.RecentCalls[i] = redacted
		}
	}
	return out, total
}

func addMask(text string, running int) (string, int) {
	redacted, n := Text(text)
	return redacted, running + n
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
