package config

import (
	"strings"
	"testing"
)

func validServerConfig() Config {
	return Config{
		DatabaseURL:       "postgres://lens:" + strings.Repeat("d", 32) + "@127.0.0.1:5432/securitylens",
		AuthOperatorToken: strings.Repeat("a", 64), AuthViewerToken: strings.Repeat("b", 64),
		BindAddr: "127.0.0.1", Port: "8080", AuthCookieSecure: true,
	}
}

func TestPilotDefaultsFailClosed(t *testing.T) {
	for _, key := range []string{"DATABASE_URL", "AUTH_OPERATOR_TOKEN", "AUTH_VIEWER_TOKEN", "AUTH_COOKIE_SECURE", "BIND_ADDR", "PORT", "SEED_ON_START"} {
		t.Setenv(key, "")
	}
	cfg := Load()
	if cfg.DatabaseURL != "" || cfg.AuthOperatorToken != "" {
		t.Fatal("credentials must have no default")
	}
	if cfg.BindAddr != "127.0.0.1" || !cfg.AuthCookieSecure || cfg.SeedOnStart {
		t.Fatal("pilot defaults must be private, secure-cookie, and unseeded")
	}
	if cfg.ValidateServer() == nil {
		t.Fatal("empty deployment config must fail")
	}
	t.Setenv("AUTH_COOKIE_SECURE", "false")
	if Load().AuthCookieSecure {
		t.Fatal("explicit local HTTP cookie setting ignored")
	}
	t.Setenv("AUTH_COOKIE_SECURE", "invalid")
	if !Load().AuthCookieSecure {
		t.Fatal("invalid cookie setting must fail secure")
	}
}

func TestValidateServerCredentials(t *testing.T) {
	tests := []struct {
		name   string
		update func(*Config)
	}{
		{"missing operator", func(c *Config) { c.AuthOperatorToken = "" }},
		{"short operator", func(c *Config) { c.AuthOperatorToken = "short" }},
		{"nonhex operator", func(c *Config) { c.AuthOperatorToken = strings.Repeat("x", 64) }},
		{"bad viewer", func(c *Config) { c.AuthViewerToken = "short" }},
		{"same token", func(c *Config) { c.AuthViewerToken = strings.ToUpper(c.AuthOperatorToken) }},
		{"missing database", func(c *Config) { c.DatabaseURL = "" }},
		{"malformed database", func(c *Config) { c.DatabaseURL = "postgres://lens:DO_NOT_ECHO_SECRET%zz@localhost/db" }},
		{"wrong scheme", func(c *Config) { c.DatabaseURL = "http://lens:" + strings.Repeat("d", 32) + "@localhost/db" }},
		{"default password", func(c *Config) { c.DatabaseURL = "postgres://lens:lens@localhost/db" }},
		{"no password", func(c *Config) { c.DatabaseURL = "postgres://lens@localhost/db" }},
		{"no username", func(c *Config) { c.DatabaseURL = "postgres://:" + strings.Repeat("d", 32) + "@localhost/db" }},
		{"no host", func(c *Config) { c.DatabaseURL = "postgres://lens:" + strings.Repeat("d", 32) + "@/db" }},
		{"query password override", func(c *Config) { c.DatabaseURL += "?password=lens" }},
		{"query user override", func(c *Config) { c.DatabaseURL += "?user=lens" }},
		{"query service override", func(c *Config) { c.DatabaseURL += "?service=default" }},
		{"malformed query", func(c *Config) { c.DatabaseURL += "?sslmode=%zz" }},
		{"empty bind", func(c *Config) { c.BindAddr = "" }},
		{"invalid port", func(c *Config) { c.Port = "70000" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validServerConfig()
			tt.update(&cfg)
			err := cfg.ValidateServer()
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			for _, secret := range []string{"DO_NOT_ECHO_SECRET", strings.Repeat("d", 32), strings.Repeat("a", 64)} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("validation error contains secret")
				}
			}
		})
	}
	cfg := validServerConfig()
	if err := cfg.ValidateServer(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cfg.AuthViewerToken = ""
	if err := cfg.ValidateServer(); err != nil {
		t.Fatalf("optional viewer rejected: %v", err)
	}
}
