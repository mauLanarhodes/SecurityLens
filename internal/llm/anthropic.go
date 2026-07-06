package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultModel is the model used for live calls unless overridden.
const DefaultModel = "claude-opus-4-8"

const (
	apiURL     = "https://api.anthropic.com/v1/messages"
	apiVersion = "2023-06-01"
)

// Anthropic is a hand-rolled Messages API client (no SDK dependency).
// Requests use adaptive thinking; sampling parameters are deliberately not
// sent (removed on current models). Retries 429/5xx/529 with backoff.
type Anthropic struct {
	APIKey  string
	Model   string
	BaseURL string
	HTTP    *http.Client
}

func NewAnthropic(apiKey, model string) *Anthropic {
	if model == "" {
		model = DefaultModel
	}
	return &Anthropic{
		APIKey:  apiKey,
		Model:   model,
		BaseURL: apiURL,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

func (a *Anthropic) Live() bool        { return true }
func (a *Anthropic) ModelName() string { return a.Model }

type anthropicRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system,omitempty"`
	Messages  []Message       `json:"messages"`
	Thinking  *thinkingConfig `json:"thinking,omitempty"`
}

type thinkingConfig struct {
	Type string `json:"type"`
}

type anthropicResponse struct {
	ID         string `json:"id"`
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (a *Anthropic) Complete(ctx context.Context, req Request) (Response, error) {
	if req.MaxTokens <= 0 {
		req.MaxTokens = 2048
	}
	body, err := json.Marshal(anthropicRequest{
		Model:     a.Model,
		MaxTokens: req.MaxTokens,
		System:    req.System,
		Messages:  req.Messages,
		Thinking:  &thinkingConfig{Type: "adaptive"},
	})
	if err != nil {
		return Response{}, err
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return Response{}, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * time.Second):
			}
		}
		resp, retryable, err := a.doOnce(ctx, body)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable {
			break
		}
	}
	return Response{}, lastErr
}

func (a *Anthropic) doOnce(ctx context.Context, body []byte) (Response, bool, error) {
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, false, err
	}
	hreq.Header.Set("x-api-key", a.APIKey)
	hreq.Header.Set("anthropic-version", apiVersion)
	hreq.Header.Set("content-type", "application/json")

	hres, err := a.HTTP.Do(hreq)
	if err != nil {
		return Response{}, true, err // network error: retryable
	}
	defer hres.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(hres.Body, 4<<20))
	if err != nil {
		return Response{}, true, err
	}

	var ar anthropicResponse
	if err := json.Unmarshal(raw, &ar); err != nil {
		return Response{}, false, fmt.Errorf("anthropic: bad response (%d): %.200s", hres.StatusCode, raw)
	}
	if hres.StatusCode != http.StatusOK {
		retryable := hres.StatusCode == 429 || hres.StatusCode >= 500
		msg := ""
		if ar.Error != nil {
			msg = ar.Error.Type + ": " + ar.Error.Message
		}
		return Response{}, retryable, fmt.Errorf("anthropic: HTTP %d %s", hres.StatusCode, msg)
	}

	// A refusal is a successful HTTP 200; check stop_reason before content.
	if ar.StopReason == "refusal" {
		return Response{}, false, fmt.Errorf("anthropic: request declined (stop_reason=refusal)")
	}
	var text string
	for _, c := range ar.Content {
		if c.Type == "text" {
			text += c.Text
		}
	}
	return Response{
		Text:         text,
		StopReason:   ar.StopReason,
		Model:        ar.Model,
		InputTokens:  ar.Usage.InputTokens,
		OutputTokens: ar.Usage.OutputTokens,
	}, false, nil
}
