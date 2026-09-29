package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const DefaultOpenAIModel = "gpt-6.1-sol"

const openAIURL = "https://api.openai.com/v1/responses"

// OpenAI implements Client using the Responses API without an SDK dependency.
// Requests use medium reasoning and disable response storage. Keys and raw
// provider error bodies are never included in errors returned to the dashboard.
type OpenAI struct {
	APIKey  string
	Model   string
	BaseURL string
	HTTP    *http.Client
}

func NewOpenAI(apiKey, model string) *OpenAI {
	if model == "" {
		model = DefaultOpenAIModel
	}
	return &OpenAI{
		APIKey: apiKey, Model: model, BaseURL: openAIURL,
		HTTP: &http.Client{Timeout: 120 * time.Second},
	}
}

func (a *OpenAI) Live() bool        { return true }
func (a *OpenAI) ModelName() string { return a.Model }

type openAIRequest struct {
	Model           string    `json:"model"`
	Instructions    string    `json:"instructions,omitempty"`
	Input           []Message `json:"input"`
	MaxOutputTokens int       `json:"max_output_tokens"`
	Store           bool      `json:"store"`
	Reasoning       struct {
		Effort string `json:"effort"`
	} `json:"reasoning"`
}

type openAIResponse struct {
	Model             string          `json:"model"`
	Status            string          `json:"status"`
	Error             json.RawMessage `json:"error"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Output []struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (a *OpenAI) Complete(ctx context.Context, req Request) (Response, error) {
	if strings.TrimSpace(a.APIKey) == "" {
		return Response{}, fmt.Errorf("openai: OPENAI_API_KEY is required")
	}
	if req.MaxTokens <= 0 {
		req.MaxTokens = featureOutputBudget
	}
	payload := openAIRequest{
		Model: a.Model, Instructions: req.System, Input: req.Messages,
		MaxOutputTokens: req.MaxTokens, Store: false,
	}
	payload.Reasoning.Effort = "medium"
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, err
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return Response{}, err
		}
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt*attempt) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Response{}, ctx.Err()
			case <-timer.C:
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

func (a *OpenAI) doOnce(ctx context.Context, body []byte) (Response, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, false, fmt.Errorf("openai: invalid endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+a.APIKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, false, ctx.Err()
		}
		return Response{}, true, fmt.Errorf("openai: network request failed")
	}
	defer res.Body.Close()
	// Inspect status before decoding: gateways can return HTML on 429/5xx.
	if res.StatusCode != http.StatusOK {
		hint := "check the model and request configuration"
		switch res.StatusCode {
		case http.StatusUnauthorized:
			hint = "check OPENAI_API_KEY"
		case http.StatusForbidden, http.StatusNotFound:
			hint = "check model access and LLM_MODEL"
		case http.StatusTooManyRequests:
			hint = "check API quota, billing, and rate limits"
		}
		return Response{}, res.StatusCode == 429 || res.StatusCode >= 500,
			fmt.Errorf("openai: HTTP %d (%s)", res.StatusCode, hint)
	}
	const maxBody = 4 << 20
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return Response{}, true, fmt.Errorf("openai: could not read response")
	}
	if len(raw) > maxBody {
		return Response{}, false, fmt.Errorf("openai: response exceeds size limit")
	}
	var decoded openAIResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Response{}, false, fmt.Errorf("openai: invalid response JSON")
	}
	if len(decoded.Error) > 0 && string(decoded.Error) != "null" {
		return Response{}, false, fmt.Errorf("openai: response reported an error")
	}
	if decoded.Status == "incomplete" {
		if decoded.IncompleteDetails != nil && decoded.IncompleteDetails.Reason == "max_output_tokens" {
			return Response{}, false, fmt.Errorf("openai: output token limit reached before completion")
		}
		return Response{}, false, fmt.Errorf("openai: incomplete response")
	}
	if decoded.Status != "completed" {
		return Response{}, false, fmt.Errorf("openai: response did not complete")
	}
	var result strings.Builder
	for _, item := range decoded.Output {
		if item.Type != "message" || item.Role != "assistant" {
			continue
		}
		for _, content := range item.Content {
			switch content.Type {
			case "refusal":
				return Response{}, false, fmt.Errorf("openai: request declined")
			case "output_text":
				result.WriteString(content.Text)
			}
		}
	}
	if strings.TrimSpace(result.String()) == "" {
		return Response{}, false, fmt.Errorf("openai: response contained no output text")
	}
	return Response{
		Text: result.String(), StopReason: "end_turn", Model: decoded.Model,
		InputTokens: decoded.Usage.InputTokens, OutputTokens: decoded.Usage.OutputTokens,
	}, false, nil
}
