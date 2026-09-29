package llm

import (
	"strings"
	"testing"

	"securitylens/internal/config"
)

func TestProviderSelection(t *testing.T) {
	cases := []struct {
		name, provider, mode, openai, anthropic, model, want, wantErr string
	}{
		{name: "default without key", want: "mock"},
		{name: "OpenAI default", openai: "openai-key", want: "gpt-6.1-sol"},
		{name: "custom OpenAI model", openai: "openai-key", model: "gpt-6-luna", want: "gpt-6-luna"},
		{name: "both keys use OpenAI", openai: "openai-key", anthropic: "anthropic-key", want: "gpt-6.1-sol"},
		{name: "wrong provider key stays mock", anthropic: "anthropic-key", want: "mock"},
		{name: "forced mock", mode: "mock", openai: "openai-key", want: "mock"},
		{name: "forced OpenAI live", mode: "live", openai: "openai-key", want: "gpt-6.1-sol"},
		{name: "missing OpenAI key", mode: "live", anthropic: "anthropic-key", wantErr: "OPENAI_API_KEY"},
		{name: "explicit Anthropic", provider: "anthropic", anthropic: "anthropic-key", openai: "openai-key", want: "claude-opus-4-8"},
		{name: "Anthropic model override", provider: "anthropic", anthropic: "anthropic-key", model: "custom-claude", want: "custom-claude"},
		{name: "Anthropic wrong key stays mock", provider: "anthropic", openai: "openai-key", want: "mock"},
		{name: "missing Anthropic key", provider: "anthropic", mode: "live", openai: "openai-key", wantErr: "ANTHROPIC_API_KEY"},
		{name: "invalid provider", provider: "typo", wantErr: "LLM_PROVIDER"},
		{name: "invalid mode", mode: "typo", openai: "openai-key", wantErr: "LLM_MODE"},
		{name: "normalized env", provider: " OpenAI ", mode: " LIVE ", openai: " openai-key ", model: " gpt-6-luna ", want: "gpt-6-luna"},
		{name: "blank key", mode: "live", openai: " \t ", wantErr: "OPENAI_API_KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LLM_PROVIDER", tc.provider)
			t.Setenv("LLM_MODE", tc.mode)
			t.Setenv("LLM_MODEL", tc.model)
			t.Setenv("OPENAI_API_KEY", tc.openai)
			t.Setenv("ANTHROPIC_API_KEY", tc.anthropic)
			cfg := config.Load()
			c, err := NewClient(cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.ModelName() != tc.want || c.Live() != (tc.want != "mock") {
				t.Fatalf("model/live = %q/%v, expected %q", c.ModelName(), c.Live(), tc.want)
			}
			switch client := c.(type) {
			case *OpenAI:
				if client.APIKey != strings.TrimSpace(tc.openai) {
					t.Fatal("OpenAI received the wrong provider key")
				}
			case *Anthropic:
				if client.APIKey != strings.TrimSpace(tc.anthropic) {
					t.Fatal("Anthropic received the wrong provider key")
				}
			}
		})
	}
}
