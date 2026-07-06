// Package llm holds the LLM integration: a hand-rolled Anthropic Messages API
// client, an interface-compatible deterministic mock, and the triage /
// investigation / rule-generation features built on top.
//
// The LLM is never invoked on the per-log hot path. Every result is tagged
// mock:true|false so the UI and API always show which path produced it.
package llm

import "context"

// Message is one conversation turn.
type Message struct {
	Role    string `json:"role"` // user | assistant
	Content string `json:"content"`
}

// Request is a completion request in provider-neutral form.
type Request struct {
	System    string
	Messages  []Message
	MaxTokens int
}

// Response is the completed text plus usage accounting.
type Response struct {
	Text         string
	StopReason   string
	Model        string
	InputTokens  int
	OutputTokens int
}

// Client abstracts the live Anthropic client and the mock.
type Client interface {
	Complete(ctx context.Context, req Request) (Response, error)
	Live() bool
	ModelName() string
}
