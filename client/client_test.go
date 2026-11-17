package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagnikc395/cerberus/client"
)

func TestCheckReturnsTheActionAndBlockedReadsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"event_id":"ev-1","accepted":true,"outcome":{"action":"quarantine","severity":"critical","violations":1}}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, client.WithToken("secret"))
	d, err := c.Check(context.Background(), client.Event{
		AgentID: "refund-agent", Kind: client.KindCompletion, Completion: "ssn 123-45-6789",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != "quarantine" || !d.Blocked() {
		t.Errorf("got %+v, want a blocking quarantine", d)
	}
	if d.EventID != "ev-1" {
		t.Errorf("event id = %q", d.EventID)
	}
}

func TestReportReturnsTheEventID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"event_id":"ev-2","accepted":true}`))
	}))
	defer srv.Close()

	id, err := client.New(srv.URL).Report(context.Background(), client.Event{AgentID: "a", Kind: client.KindPrompt, Prompt: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "ev-2" {
		t.Errorf("id = %q", id)
	}
}

func TestServerErrorsCarryTheMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"agent_id is required"}`))
	}))
	defer srv.Close()

	_, err := client.New(srv.URL).Report(context.Background(), client.Event{Kind: client.KindPrompt})
	if err == nil {
		t.Fatal("a 400 was not reported as an error")
	}
	if got := err.Error(); got == "" || !contains(got, "agent_id is required") {
		t.Errorf("error = %q, want the server's message", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
