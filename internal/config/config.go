// Package config loads runtime configuration from the environment.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string
	RedisAddr   string
	Port        string
	BindAddr    string

	AuthOperatorToken string
	AuthViewerToken   string
	AuthCookieSecure  bool

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
		DatabaseURL:       strings.TrimSpace(os.Getenv("DATABASE_URL")),
		RedisAddr:         getenv("REDIS_ADDR", "127.0.0.1:6379"),
		Port:              getenv("PORT", "8080"),
		BindAddr:          getenv("BIND_ADDR", "127.0.0.1"),
		AuthOperatorToken: strings.TrimSpace(os.Getenv("AUTH_OPERATOR_TOKEN")),
		AuthViewerToken:   strings.TrimSpace(os.Getenv("AUTH_VIEWER_TOKEN")),
		AuthCookieSecure:  getbool("AUTH_COOKIE_SECURE", true),
		AnthropicAPIKey:   strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")),
		OpenAIAPIKey:      strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
		LLMProvider:       strings.ToLower(strings.TrimSpace(getenv("LLM_PROVIDER", "openai"))),
		LLMModel:          strings.TrimSpace(os.Getenv("LLM_MODEL")),
		LLMMode:           strings.ToLower(strings.TrimSpace(getenv("LLM_MODE", "auto"))),
		SeedOnStart:       getbool("SEED_ON_START", false),
		SeedLogs:          getint("SEED_LOGS", 200000),
		SeedDays:          getint("SEED_DAYS", 21),
		SeedSeed:          int64(getint("SEED_SEED", 1)),
		SweepInterval:     getdur("SWEEP_INTERVAL", 15*time.Second),
		DetectLag:         getdur("DETECT_LAG", 5*time.Second),
		SweepStep:         getdur("SWEEP_STEP", 10*time.Minute),
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

// ValidateAuth also protects embedded routers when startup validation is omitted.
// Generate tokens from 32 random bytes, for example with openssl rand -hex 32.
func (c Config) ValidateAuth() error {
	operator, err := hex.DecodeString(c.AuthOperatorToken)
	if err != nil || len(operator) != 32 {
		return errors.New("AUTH_OPERATOR_TOKEN must contain 64 hexadecimal characters")
	}
	if c.AuthViewerToken != "" {
		viewer, err := hex.DecodeString(c.AuthViewerToken)
		if err != nil || len(viewer) != 32 {
			return errors.New("AUTH_VIEWER_TOKEN must contain 64 hexadecimal characters")
		}
		if bytes.Equal(operator, viewer) {
			return errors.New("AUTH_OPERATOR_TOKEN and AUTH_VIEWER_TOKEN must differ")
		}
	}
	return nil
}

// ValidateServer checks pilot credentials before opening connections or creating
// an LLM client. Validation errors never include credential values.
func (c Config) ValidateServer() error {
	if err := c.ValidateAuth(); err != nil {
		return err
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil || u == nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.User == nil || u.User.Username() == "" {
		return errors.New("DATABASE_URL must be a PostgreSQL URL with a host, username, and password")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.New("DATABASE_URL contains invalid query parameters")
	}
	if query.Has("password") || query.Has("user") || query.Has("service") {
		return errors.New("DATABASE_URL must place credentials in its user information, not query parameters")
	}
	password, ok := u.User.Password()
	if !ok || len(password) < 32 {
		return errors.New("DATABASE_URL must contain a generated password of at least 32 characters")
	}
	if strings.TrimSpace(c.BindAddr) == "" {
		return errors.New("BIND_ADDR must be set")
	}
	port, err := strconv.Atoi(c.Port)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("PORT must be between 1 and 65535")
	}
	return nil
}
