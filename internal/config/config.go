// Package config loads runtime configuration from the environment.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string
	RedisAddr   string
	Port        string

	AnthropicAPIKey string
	OpenAIAPIKey    string
	LLMProvider     string // openai | anthropic
	LLMModel        string // empty selects the provider's default
	LLMMode         string // auto | mock | live

	SeedOnStart bool
	SeedLogs    int
	SeedDays    int
	SeedSeed    int64

	SweepInterval time.Duration // live sweep cadence
	DetectLag     time.Duration // wait before a window is considered settled
	SweepStep     time.Duration // window step; window length is 2*step
}

func Load() Config {
	return Config{
		DatabaseURL:     getenv("DATABASE_URL", "postgres://lens:lens@127.0.0.1:5432/securitylens?sslmode=disable"),
		RedisAddr:       getenv("REDIS_ADDR", "127.0.0.1:6379"),
		Port:            getenv("PORT", "8080"),
		AnthropicAPIKey: strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")),
		OpenAIAPIKey:    strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		LLMProvider:     strings.ToLower(strings.TrimSpace(getenv("LLM_PROVIDER", "openai"))),
		LLMModel:        strings.TrimSpace(os.Getenv("LLM_MODEL")),
		LLMMode:         strings.ToLower(strings.TrimSpace(getenv("LLM_MODE", "auto"))),
		SeedOnStart:     getbool("SEED_ON_START", false),
		SeedLogs:        getint("SEED_LOGS", 200000),
		SeedDays:        getint("SEED_DAYS", 21),
		SeedSeed:        int64(getint("SEED_SEED", 1)),
		SweepInterval:   getdur("SWEEP_INTERVAL", 15*time.Second),
		DetectLag:       getdur("DETECT_LAG", 5*time.Second),
		SweepStep:       getdur("SWEEP_STEP", 10*time.Minute),
	}
}

// LLMLive reports whether the selected provider should make live calls.
func (c Config) LLMLive() bool {
	switch c.LLMMode {
	case "live":
		return true
	case "mock":
		return false
	default: // auto
		if c.LLMProvider == "openai" {
			return c.OpenAIAPIKey != ""
		}
		return c.AnthropicAPIKey != ""
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getint(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getbool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func getdur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
