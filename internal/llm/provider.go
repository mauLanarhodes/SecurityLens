package llm

import (
	"fmt"

	"securitylens/internal/config"
)

// NewClient selects exactly one provider. A key for a different provider never
// enables live calls, and forcing live mode without the selected key is an error.
func NewClient(cfg config.Config) (Client, error) {
	if cfg.LLMMode != "auto" && cfg.LLMMode != "mock" && cfg.LLMMode != "live" {
		return nil, fmt.Errorf("LLM_MODE must be auto, mock, or live")
	}
	if cfg.LLMProvider != "openai" && cfg.LLMProvider != "anthropic" {
		return nil, fmt.Errorf("LLM_PROVIDER must be openai or anthropic")
	}
	if !cfg.LLMLive() {
		return &Mock{}, nil
	}
	if cfg.LLMProvider == "openai" {
		if cfg.OpenAIAPIKey == "" {
			return nil, fmt.Errorf("OPENAI_API_KEY is required when LLM_PROVIDER=openai and LLM_MODE=live")
		}
		return NewOpenAI(cfg.OpenAIAPIKey, cfg.LLMModel), nil
	}
	if cfg.AnthropicAPIKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic and LLM_MODE=live")
	}
	return NewAnthropic(cfg.AnthropicAPIKey, cfg.LLMModel), nil
}
