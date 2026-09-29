package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const completedOpenAIResponse = `{
  "status": "completed", "model": "gpt-6.1-sol", "error": null,
  "output": [
    {"type":"reasoning", "summary":[]},
    {"type":"message", "role":"assistant", "content":[
      {"type":"output_text", "text":"{\"verdict\":"},
      {"type":"output_text", "text":"\"needs_review\"}"}
    ]}
  ],
  "usage":{"input_tokens":321,"output_tokens":700,"output_tokens_details":{"reasoning_tokens":680}}
}`

func TestOpenAIResponsesProtocol(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/responses" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-openai-key" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing Responses API authentication/content type")
		}
		if r.Header.Get("x-api-key") != "" || r.Header.Get("anthropic-version") != "" {
			t.Error("Anthropic headers must not be sent to OpenAI")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if body["model"] != "custom-model" || body["instructions"] != "Return JSON." || body["max_output_tokens"] != float64(12000) || body["store"] != false {
			t.Errorf("incorrect Responses payload: %#v", body)
		}
		reasoning, _ := body["reasoning"].(map[string]any)
		if reasoning["effort"] != "medium" {
			t.Errorf("incorrect reasoning: %#v", reasoning)
		}
		input, _ := body["input"].([]any)
		want := []Message{{Role: "user", Content: "First alert"}, {Role: "assistant", Content: "Prior result"}, {Role: "user", Content: "Review again"}}
		if len(input) != len(want) {
			t.Errorf("incorrect input count: %d", len(input))
		} else {
			for i, msg := range want {
				got, _ := input[i].(map[string]any)
				if got["role"] != msg.Role || got["content"] != msg.Content {
					t.Errorf("input %d = %#v", i, got)
				}
			}
		}
		for _, key := range []string{"messages", "max_tokens", "thinking", "temperature"} {
			if _, ok := body[key]; ok {
				t.Errorf("unexpected parameter %s", key)
			}
		}
		io.WriteString(w, completedOpenAIResponse)
	}))
	defer server.Close()
	c := NewOpenAI("test-openai-key", "custom-model")
	c.BaseURL = server.URL + "/v1/responses"
	response, err := c.Complete(context.Background(), Request{
		System: "Return JSON.", MaxTokens: 12000,
		Messages: []Message{{Role: "user", Content: "First alert"}, {Role: "assistant", Content: "Prior result"}, {Role: "user", Content: "Review again"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Text != `{"verdict":"needs_review"}` || response.Model != "gpt-6.1-sol" || response.StopReason != "end_turn" {
		t.Fatalf("incorrect response: %+v", response)
	}
	if response.InputTokens != 321 || response.OutputTokens != 700 {
		t.Fatalf("usage must include reasoning tokens: %+v", response)
	}
}

func TestOpenAIDefaultModelAndBudget(t *testing.T) {
	t.Parallel()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["model"] != "gpt-6.1-sol" || body["max_output_tokens"] != float64(25000) {
			t.Errorf("unexpected defaults: %#v", body)
		}
		io.WriteString(w, completedOpenAIResponse)
	}))
	defer s.Close()
	c := NewOpenAI("test-key", "")
	c.BaseURL = s.URL
	if _, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: "Review"}}}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAIRejectsUnusableResponses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, body, want string
		status           int
	}{
		{"unauthorized", `{"error":{"message":"test-secret-key"}}`, "OPENAI_API_KEY", 401},
		{"bad request", `{"error":{"message":"test-secret-key"}}`, "HTTP 400", 400},
		{"model access", `{}`, "model access", 403},
		{"missing model", `{}`, "LLM_MODEL", 404},
		{"invalid JSON", "test-secret-key", "invalid response JSON", 200},
		{"refusal", `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"partial"},{"type":"refusal","refusal":"test-secret-key"}]}]}`, "declined", 200},
		{"token limit", `{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"partial"}]}]}`, "token limit", 200},
		{"incomplete", `{"status":"incomplete","incomplete_details":{"reason":"content_filter"}}`, "incomplete response", 200},
		{"failed", `{"status":"failed","error":{"message":"test-secret-key"}}`, "reported an error", 200},
		{"pending", `{"status":"in_progress"}`, "did not complete", 200},
		{"empty", `{"status":"completed","output":[]}`, "no output text", 200},
		{"wrong role", `{"status":"completed","output":[{"type":"message","role":"user","content":[{"type":"output_text","text":"untrusted"}]}]}`, "no output text", 200},
		{"too large", strings.Repeat("x", (4<<20)+1), "size limit", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer s.Close()
			c := NewOpenAI("test-secret-key", "")
			c.BaseURL = s.URL
			response, err := c.Complete(context.Background(), Request{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "test-secret-key") || response.Text != "" {
				t.Fatalf("error leaked a key or returned partial output: %v / %+v", err, response)
			}
			if calls.Load() != 1 {
				t.Fatalf("permanent failure retried %d times", calls.Load())
			}
		})
	}
}

func TestOpenAIRetriesTemporaryFailures(t *testing.T) {
	t.Parallel()
	for _, status := range []int{429, 502} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(status)
					io.WriteString(w, "<html>temporary gateway failure</html>")
					return
				}
				io.WriteString(w, completedOpenAIResponse)
			}))
			defer s.Close()
			c := NewOpenAI("test-key", "")
			c.BaseURL = s.URL
			if _, err := c.Complete(context.Background(), Request{}); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatalf("requests = %d, want 2", calls.Load())
			}
		})
	}
}

func TestOpenAIRetryLimit(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
	}))
	defer s.Close()
	c := NewOpenAI("test-key", "")
	c.BaseURL = s.URL
	if _, err := c.Complete(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected exhausted retries: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("requests = %d, want 3", calls.Load())
	}
}

func TestOpenAICancellationAndMissingKey(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Error("request should not have been sent")
	}))
	defer s.Close()
	c := NewOpenAI("test-key", "")
	c.BaseURL = s.URL
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Complete(ctx, Request{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
	c.APIKey = " "
	if _, err := c.Complete(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Fatalf("expected missing key: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("requests = %d, want 0", calls.Load())
	}
}
