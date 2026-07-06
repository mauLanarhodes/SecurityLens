package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"securitylens/internal/model"
	"securitylens/internal/store"
)

// Service wires a Client (live or mock) to the Redis result cache and the
// llm_usage accounting table.
type Service struct {
	Client Client
	Redis  *redis.Client
	Store  *store.Store
}

func NewService(c Client, rdb *redis.Client, st *store.Store) *Service {
	return &Service{Client: c, Redis: rdb, Store: st}
}

func (s *Service) record(ctx context.Context, feature string, resp Response, cached bool, started time.Time) {
	_ = s.Store.InsertLLMUsage(ctx, store.LLMUsage{
		Feature:      feature,
		Model:        s.Client.ModelName(),
		Mock:         !s.Client.Live(),
		Cached:       cached,
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
		LatencyMS:    int(time.Since(started).Milliseconds()),
	})
}

// Triage produces (and caches) an LLM verdict for an alert. The cache key
// covers the alert's identity and evidence, so re-requesting triage for an
// unchanged alert is free.
func (s *Service) Triage(ctx context.Context, a model.Alert) (model.Triage, error) {
	started := time.Now()
	evJSON, _ := json.Marshal(a.Evidence)
	key := "llm:triage:" + hashKey(a.DedupKey, string(evJSON), s.Client.ModelName())

	if raw, err := s.Redis.Get(ctx, key).Result(); err == nil {
		var t model.Triage
		if json.Unmarshal([]byte(raw), &t) == nil {
			t.Cached = true
			s.record(ctx, "triage", Response{}, true, started)
			return t, nil
		}
	}

	prompt := fmt.Sprintf(`TASK: triage

You are a senior SOC analyst triaging one alert. Assess whether it is a true
positive and what to do next.

ALERT:
  type: %s
  severity: %s
  entity: %s
  title: %s
  window: %s .. %s
  evidence: %s

Respond with ONLY a JSON object:
{"verdict": "likely_true_positive"|"likely_false_positive"|"needs_review",
 "confidence": 0.0-1.0,
 "reasoning": "...",
 "next_steps": ["...", "..."]}`,
		a.AlertType, a.Severity, a.Entity, a.Title,
		a.WindowStart.Format(time.RFC3339), a.WindowEnd.Format(time.RFC3339), evJSON)

	resp, err := s.Client.Complete(ctx, Request{
		Messages:  []Message{{Role: "user", Content: prompt}},
		MaxTokens: 1024,
	})
	if err != nil {
		return model.Triage{}, err
	}
	var t model.Triage
	if err := json.Unmarshal([]byte(extractJSON(resp.Text)), &t); err != nil {
		return model.Triage{}, fmt.Errorf("triage: unparseable LLM output: %w", err)
	}
	t.Model = s.Client.ModelName()
	t.Mock = !s.Client.Live()
	t.At = time.Now().UTC()

	b, _ := json.Marshal(t)
	s.Redis.Set(ctx, key, b, 24*time.Hour)
	s.record(ctx, "triage", resp, false, started)
	return t, nil
}

// Investigation is the threat-hunting assistant's output for one alert.
type Investigation struct {
	Hypothesis         string   `json:"hypothesis"`
	BenignExplanations []string `json:"benign_explanations"`
	PivotQueries       []string `json:"pivot_queries"`
	ContextEvents      int      `json:"context_events"`
	Model              string   `json:"model"`
	Mock               bool     `json:"mock"`
}

// Investigate reasons over an alert plus the entity's surrounding activity.
func (s *Service) Investigate(ctx context.Context, a model.Alert) (Investigation, error) {
	started := time.Now()
	activity, err := s.Store.EntityActivity(ctx, a.Username, a.SrcIP,
		a.WindowStart.Add(-30*time.Minute), a.WindowEnd.Add(30*time.Minute), 200)
	if err != nil {
		return Investigation{}, err
	}
	var lines []string
	for _, e := range activity {
		lines = append(lines, fmt.Sprintf("%s %s %s user=%s src=%s dst=%s status=%s bytes=%d %s",
			e.TS.Format("15:04:05"), e.Source, e.EventType, e.Username, e.SrcIP, e.DstHost, e.Status, e.BytesOut, e.Message))
	}
	evJSON, _ := json.Marshal(a.Evidence)

	prompt := fmt.Sprintf(`TASK: investigate

You are a threat hunter investigating one alert with the entity's surrounding
activity (±30 minutes). Form an attack hypothesis, list benign explanations
that could also account for it, and propose SQL pivot queries over the logs
table (columns: ts, source, event_type, username, src_ip, dst_host, status,
bytes_out, message).

ALERT: type=%s entity=%s title=%q window=%s..%s
EVIDENCE: %s

SURROUNDING ACTIVITY (%d events):
%s

Respond with ONLY a JSON object:
{"hypothesis": "...", "benign_explanations": ["..."], "pivot_queries": ["..."]}`,
		a.AlertType, a.Entity, a.Title,
		a.WindowStart.Format(time.RFC3339), a.WindowEnd.Format(time.RFC3339),
		evJSON, len(activity), strings.Join(lines, "\n"))

	resp, err := s.Client.Complete(ctx, Request{
		Messages:  []Message{{Role: "user", Content: prompt}},
		MaxTokens: 1500,
	})
	if err != nil {
		return Investigation{}, err
	}
	var inv Investigation
	if err := json.Unmarshal([]byte(extractJSON(resp.Text)), &inv); err != nil {
		return Investigation{}, fmt.Errorf("investigate: unparseable LLM output: %w", err)
	}
	inv.ContextEvents = len(activity)
	inv.Model = s.Client.ModelName()
	inv.Mock = !s.Client.Live()
	s.record(ctx, "investigate", resp, false, started)
	return inv, nil
}

// GenerateRule turns an English detection idea into Go code implementing the
// rule scaffold's Detect function. The code is returned for compilation by
// internal/rulegen; it is never executed here.
func (s *Service) GenerateRule(ctx context.Context, description string) (string, error) {
	started := time.Now()
	prompt := fmt.Sprintf(`TASK: rulegen

Write a Go detection rule for a security log pipeline.

DESCRIPTION: %s

The code must be a single file: package rule, standard library only, and it
must implement exactly this function against these pre-declared types (do NOT
re-declare Event or Finding; they already exist in the package):

  func Detect(events []Event) []Finding

  // provided by the scaffold:
  type Event struct {
      TS        time.Time
      Source    string // cloudtrail | ssh | nginx | app
      EventType string // console_login, api_call, ssh_login, http_request, app_log, permission_change, data_transfer
      Username  string
      SrcIP     string
      DstHost   string
      Status    string // success | failure | denied | info
      BytesOut  int64
      Message   string
  }
  type Finding struct {
      Entity   string
      Title    string
      Severity string // critical | high | medium | low
      Count    int
  }

Respond with ONLY the Go code in a single fenced code block.`, description)

	resp, err := s.Client.Complete(ctx, Request{
		Messages:  []Message{{Role: "user", Content: prompt}},
		MaxTokens: 2048,
	})
	if err != nil {
		return "", err
	}
	s.record(ctx, "rulegen", resp, false, started)
	return ExtractCode(resp.Text), nil
}

func hashKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// extractJSON returns the first balanced {...} object in s, tolerating prose
// or code fences around it.
func extractJSON(s string) string {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return s
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return s[start:]
}

// ExtractCode pulls the contents of the first fenced code block, or returns
// the input unchanged if there is no fence.
func ExtractCode(s string) string {
	i := strings.Index(s, "```")
	if i < 0 {
		return strings.TrimSpace(s)
	}
	rest := s[i+3:]
	if j := strings.IndexByte(rest, '\n'); j >= 0 {
		rest = rest[j+1:] // drop the language tag line
	}
	if k := strings.Index(rest, "```"); k >= 0 {
		rest = rest[:k]
	}
	return strings.TrimSpace(rest)
}
