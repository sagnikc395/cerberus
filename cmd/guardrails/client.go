package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// client talks to a running control plane. The CLI uses the same HTTP API an
// SDK does, so anything it can do, an agent can do.
type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(base string) *client {
	if base == "" {
		base = os.Getenv("CERBERUS_URL")
	}
	if base == "" {
		base = "http://localhost:8080"
	}
	return &client{
		base:  base,
		token: os.Getenv("CERBERUS_TOKEN"),
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(payload, &apiErr)
		if apiErr.Error == "" {
			apiErr.Error = string(payload)
		}
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, apiErr.Error)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(payload, out)
}
