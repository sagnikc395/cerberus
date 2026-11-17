package secrets

import (
	"context"
	"testing"

	"github.com/sagnikc395/cerberus/internal/core"
)

func TestScanFindsProviderKeysAndSkipsPlaceholders(t *testing.T) {
	flagged := map[string]string{
		"AKIA2E4ZXQ7GHQ8MNPQR":                     "aws_access_key_id",
		"ghp_16C7e42F292c6912E7710c838347Ae178B4a": "github_token",
		"postgres://app:s3cr3tpassw0rd@db/refunds": "postgres_url",
		"-----BEGIN RSA PRIVATE KEY-----":          "private_key_block",
	}
	for text, rule := range flagged {
		matches := Scan(text)
		if len(matches) == 0 {
			t.Errorf("%q was not detected, want %s", text, rule)
			continue
		}
		if matches[0].Rule != rule {
			t.Errorf("%q matched %s, want %s", text, matches[0].Rule, rule)
		}
	}
	for _, text := range []string{
		"api_key=YOUR_API_KEY_HERE",
		"token = ${REFUNDS_TOKEN}",
		"Set your API key in the dashboard under Settings.",
		"AKIAIOSFODNN7EXAMPLE", // AWS's own documentation key
	} {
		if got := Scan(text); len(got) != 0 {
			t.Errorf("%q was reported as a secret: %+v", text, got)
		}
	}
}

func TestMaskKeepsTheShapeAndNotTheValue(t *testing.T) {
	m := Match{Rule: "github_token", Value: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}
	got := Mask(m)
	if got != "github_token (40 chars, ends …6789)" {
		t.Errorf("Mask = %q", got)
	}
}

func TestLeakCheckReadsCompletionsAndToolArguments(t *testing.T) {
	c := NewLeakCheck()
	v, err := c.Run(context.Background(), core.Event{
		ToolCall: &core.ToolCall{Name: "send_email", Args: map[string]any{"body": "key AKIA2E4ZXQ7GHQ8MNPQR"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Flagged() {
		t.Fatal("a credential in tool arguments was not flagged")
	}
	if v.Evidence[0].Field != core.FieldToolArgs {
		t.Errorf("evidence field = %s, want tool_args", v.Evidence[0].Field)
	}
}
