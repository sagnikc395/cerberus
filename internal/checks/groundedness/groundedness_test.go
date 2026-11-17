package groundedness

import (
	"context"
	"errors"
	"testing"

	"github.com/sagnikc395/cerberus/internal/core"
)

type stubJudge struct {
	score float64
	calls int
	err   error
}

func (j *stubJudge) Judge(context.Context, string, []core.Document) (float64, string, float64, error) {
	j.calls++
	return j.score, "stub", 0.002, j.err
}

func TestOverlapPreFilterKeepsTheJudgeOutOfTheLoop(t *testing.T) {
	judge := &stubJudge{score: 0.9}
	c := New()
	c.Judge = judge
	c.SampleRate = 1
	docs := []core.Document{{Source: "kb", Content: "Standard shipping takes three to five business days."}}

	grounded := core.Event{ID: "e1", Completion: "Standard shipping takes three to five business days.", Context: docs}
	v, err := c.Run(context.Background(), grounded)
	if err != nil {
		t.Fatal(err)
	}
	if judge.calls != 0 {
		t.Error("the judge was paid for an answer that quotes the source")
	}
	if v.Flagged() {
		t.Errorf("a grounded answer was flagged: %+v", v)
	}

	invented := core.Event{ID: "e2", Completion: "Delivery is guaranteed overnight worldwide with insurance.", Context: docs}
	v, err = c.Run(context.Background(), invented)
	if err != nil {
		t.Fatal(err)
	}
	if judge.calls != 1 {
		t.Errorf("the judge ran %d times, want once", judge.calls)
	}
	if !v.Flagged() {
		t.Errorf("an unsupported answer was not flagged: %+v", v)
	}
	if v.CostUSD == 0 {
		t.Error("the judge's cost was not attributed to the verdict")
	}
}

func TestSamplingIsDeterministicInTheEventID(t *testing.T) {
	c := New()
	c.SampleRate = 0.5
	ev := core.Event{ID: "stable-id", Completion: "x", Context: []core.Document{{Content: "y"}}}
	first := c.AppliesTo(ev)
	for i := 0; i < 20; i++ {
		if c.AppliesTo(ev) != first {
			t.Fatal("sampling is not stable for one event id, so a replay would judge different events")
		}
	}
	c.SampleRate = 0
	if c.AppliesTo(ev) {
		t.Error("a zero sample rate still judged an event")
	}
	c.SampleRate = 1
	if !c.AppliesTo(ev) {
		t.Error("a full sample rate skipped an event")
	}
}

func TestJudgeFailureIsReportedNotSwallowed(t *testing.T) {
	c := New()
	c.SampleRate = 1
	c.Judge = &stubJudge{err: errors.New("provider down")}
	_, err := c.Run(context.Background(), core.Event{
		ID: "e3", Completion: "Delivery is guaranteed overnight worldwide.",
		Context: []core.Document{{Content: "Standard shipping takes three to five business days."}},
	})
	if err == nil {
		t.Fatal("a judge failure looked like a clean verdict")
	}
}

func TestParseJudgementToleratesAWrappedObject(t *testing.T) {
	score, rationale, err := parseJudgement("Here you go:\n```json\n{\"unsupported_score\": 0.8, \"rationale\": \"no source\"}\n```")
	if err != nil {
		t.Fatal(err)
	}
	if score != 0.8 || rationale != "no source" {
		t.Errorf("got %v %q", score, rationale)
	}
	if _, _, err := parseJudgement("I cannot help with that"); err == nil {
		t.Error("a response with no JSON was accepted")
	}
	if _, _, err := parseJudgement(`{"unsupported_score": 4}`); err == nil {
		t.Error("a score outside 0..1 was accepted")
	}
}
