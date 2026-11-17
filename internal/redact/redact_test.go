package redact

import (
	"strings"
	"testing"

	"github.com/sagnikc395/cerberus/internal/core"
)

func TestTextMaskingPreservesOffsets(t *testing.T) {
	text := "ssn 123-45-6789 and card 4242 4242 4242 4242 on file"
	masked, n := Text(text)
	if n != 2 {
		t.Fatalf("masked %d values, want 2: %q", n, masked)
	}
	if len(masked) != len(text) {
		t.Fatalf("redaction changed the length: %d -> %d (%q)", len(text), len(masked), masked)
	}
	if strings.Contains(masked, "123-45-6789") || strings.Contains(masked, "4242 4242 4242 4242") {
		t.Fatalf("value survived redaction: %q", masked)
	}
	if !strings.Contains(masked, "ssn") || !strings.Contains(masked, "on file") {
		t.Fatalf("surrounding text was damaged: %q", masked)
	}
}

func TestEventRedactsEveryTextCarrier(t *testing.T) {
	ev := core.Event{
		ID:         "ev-1",
		AgentID:    "refund-agent",
		Prompt:     "refund for dana.reyes@example.com",
		Completion: "the key is AKIA2E4ZXQ7GHQ8MNPQR",
		Context:    []core.Document{{Source: "kb", Content: "customer ssn 123-45-6789"}},
		ToolCall: &core.ToolCall{
			Name: "send_email",
			Args: map[string]any{"to": "ops-team", "body": "card 4111-1111-1111-1111", "retries": 2},
		},
	}
	out, n := Event(ev)
	if n != 4 {
		t.Errorf("masked %d values, want 4", n)
	}
	if strings.Contains(out.Prompt, "dana.reyes@example.com") {
		t.Error("prompt was not redacted")
	}
	if strings.Contains(out.Completion, "AKIA2E4ZXQ7GHQ8MNPQR") {
		t.Error("completion was not redacted")
	}
	if strings.Contains(out.Context[0].Content, "123-45-6789") {
		t.Error("context was not redacted")
	}
	if body := out.ToolCall.Args["body"].(string); strings.Contains(body, "4111-1111-1111-1111") {
		t.Error("tool arguments were not redacted")
	}
	if out.ToolCall.Args["retries"] != 2 {
		t.Error("a non-string argument was altered")
	}
	// The original must not be mutated: the raw event is still being evaluated.
	if !strings.Contains(ev.Prompt, "dana.reyes@example.com") {
		t.Error("redaction mutated the input event")
	}
}
