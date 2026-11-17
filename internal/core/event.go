// Package core holds the types every other package shares: the event an agent
// sends, the verdict a check returns, and the Check interface itself.
package core

import "time"

// Kind is the part of an agent's turn an event carries.
type Kind string

const (
	// KindPrompt is what the agent is about to send to the model.
	KindPrompt Kind = "prompt"
	// KindCompletion is what the model produced.
	KindCompletion Kind = "completion"
	// KindToolCall is a tool invocation the agent decided to make.
	KindToolCall Kind = "tool_call"
	// KindToolResult is what a tool returned.
	KindToolResult Kind = "tool_result"
)

// Field names the part of an event a span points into. Evidence spans are
// offsets into one field's text, so a reviewer can see exactly what fired.
type Field string

const (
	FieldPrompt     Field = "prompt"
	FieldCompletion Field = "completion"
	FieldContext    Field = "context"
	FieldToolArgs   Field = "tool_args"
)

// Span is a half-open byte range [Start,End) in one field of an event.
type Span struct {
	Field Field  `json:"field"`
	Index int    `json:"index,omitempty"` // which context document, when Field is FieldContext
	Start int    `json:"start"`
	End   int    `json:"end"`
	Text  string `json:"text"` // redacted before persistence; see internal/redact
	Note  string `json:"note,omitempty"`
}

// Document is untrusted material that reached the model: a retrieved chunk, a
// web page, a prior tool result. Indirect injection lives here.
type Document struct {
	Source  string `json:"source"`
	Content string `json:"content"`
	// Trusted marks content the operator vouches for (system prompt, own
	// database). Untrusted documents are the ones injection checks read.
	Trusted bool `json:"trusted"`
}

// ToolCall is one tool invocation.
type ToolCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args,omitempty"`
	// CallID lets repeated-call detection group retries of the same call.
	CallID string `json:"call_id,omitempty"`
}

// Usage is the token spend attributed to this event.
type Usage struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	CostUSD          float64 `json:"cost_usd,omitempty"`
}

// Total is the event's token count.
func (u Usage) Total() int { return u.PromptTokens + u.CompletionTokens }

// Event is one unit of agent traffic. It is the input to every check and the
// unit of durable evaluation: one event, one workflow.
type Event struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	SessionID string    `json:"session_id,omitempty"`
	Kind      Kind      `json:"kind"`
	CreatedAt time.Time `json:"created_at"`

	Prompt     string     `json:"prompt,omitempty"`
	Completion string     `json:"completion,omitempty"`
	Context    []Document `json:"context,omitempty"`
	ToolCall   *ToolCall  `json:"tool_call,omitempty"`
	Usage      Usage      `json:"usage,omitempty"`

	// Session carries the running state a single event cannot see on its own:
	// tokens spent so far, recent tool calls. Cost checks read it.
	Session SessionState `json:"session,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

// SessionState is the rolling view of a session an event is evaluated against.
type SessionState struct {
	TokensSpent  int        `json:"tokens_spent,omitempty"`
	TurnCount    int        `json:"turn_count,omitempty"`
	RecentCalls  []ToolCall `json:"recent_calls,omitempty"`
	StartedAt    time.Time  `json:"started_at,omitempty"`
	CostSpentUSD float64    `json:"cost_spent_usd,omitempty"`
}

// Text returns the field a span addresses, so evidence can be resolved back to
// the text that produced it.
func (e Event) Text(f Field, index int) string {
	switch f {
	case FieldPrompt:
		return e.Prompt
	case FieldCompletion:
		return e.Completion
	case FieldContext:
		if index >= 0 && index < len(e.Context) {
			return e.Context[index].Content
		}
	case FieldToolArgs:
		if e.ToolCall != nil {
			return encodeArgs(e.ToolCall.Args)
		}
	}
	return ""
}

// Untrusted returns the context documents an injection check should read.
func (e Event) Untrusted() []int {
	var out []int
	for i, d := range e.Context {
		if !d.Trusted {
			out = append(out, i)
		}
	}
	return out
}
