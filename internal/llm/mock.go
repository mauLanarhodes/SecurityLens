package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"
)

// Mock is a deterministic, interface-compatible stand-in used when no
// ANTHROPIC_API_KEY is present. It returns output of the same JSON shape as
// the live model for each feature, derived only from the request content, so
// the entire pipeline and every dashboard view are exercisable offline and
// repeatably. All results flow through the same parsing paths as live output.
type Mock struct{}

func (m *Mock) Live() bool        { return false }
func (m *Mock) ModelName() string { return "mock" }

func (m *Mock) Complete(_ context.Context, req Request) (Response, error) {
	prompt := req.System + "\n" + flatten(req.Messages)
	h := fnv.New32a()
	h.Write([]byte(prompt))
	seed := h.Sum32()

	var text string
	switch {
	case strings.Contains(prompt, "TASK: triage"):
		text = m.triage(prompt, seed)
	case strings.Contains(prompt, "TASK: investigate"):
		text = m.investigate(prompt, seed)
	case strings.Contains(prompt, "TASK: rulegen"):
		text = m.rulegen(prompt)
	default:
		text = "mock response"
	}
	return Response{
		Text:         text,
		StopReason:   "end_turn",
		Model:        "mock",
		InputTokens:  len(prompt) / 4,
		OutputTokens: len(text) / 4,
	}, nil
}

func flatten(ms []Message) string {
	var b strings.Builder
	for _, m := range ms {
		b.WriteString(m.Content)
		b.WriteByte('\n')
	}
	return b.String()
}

func pickAlertType(prompt string) string {
	for _, t := range []string{
		"credential_stuffing", "privilege_escalation", "sensitive_data_exposure",
		"identity_anomaly", "lateral_movement", "off_hours_access", "data_exfiltration",
	} {
		if strings.Contains(prompt, t) {
			return t
		}
	}
	return "unknown"
}

func (m *Mock) triage(prompt string, seed uint32) string {
	t := pickAlertType(prompt)
	verdicts := []string{"likely_true_positive", "likely_true_positive", "needs_review"}
	verdict := verdicts[seed%3]
	conf := 0.62 + float64(seed%30)/100
	out := map[string]any{
		"verdict":    verdict,
		"confidence": conf,
		"reasoning": fmt.Sprintf("[mock] The evidence pattern is consistent with %s: the event counts exceed the "+
			"detector threshold and the activity is concentrated on a single entity within a short window. "+
			"No benign explanation in the surrounding context accounts for the full volume.", t),
		"next_steps": []string{
			"Confirm the affected identity/source in the identity provider audit log",
			"Check the entity's activity in the 24h before the alert window",
			"If confirmed, follow the containment step in the attached runbook",
		},
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func (m *Mock) investigate(prompt string, seed uint32) string {
	t := pickAlertType(prompt)
	out := map[string]any{
		"hypothesis": fmt.Sprintf("[mock] An adversary is conducting %s against this entity; the surrounding "+
			"activity shows the anomalous events are clustered and not part of the entity's routine baseline.", t),
		"benign_explanations": []string{
			"A scheduled automation or migration job running under a user identity",
			"A staff member travelling or working unusual hours with legitimate access",
		},
		"pivot_queries": []string{
			"SELECT * FROM logs WHERE username = $entity AND ts BETWEEN $window_start - interval '1 day' AND $window_end ORDER BY ts",
			"SELECT src_ip, count(*) FROM logs WHERE username = $entity GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
			"SELECT dst_host, count(*) FROM logs WHERE username = $entity AND event_type = 'ssh_login' GROUP BY 1",
		},
	}
	b, _ := json.Marshal(out)
	_ = seed
	return string(b)
}

func (m *Mock) rulegen(prompt string) string {
	// Extract a threshold-ish number from the description if present.
	desc := "custom rule"
	if i := strings.Index(prompt, "DESCRIPTION:"); i >= 0 {
		desc = strings.TrimSpace(strings.Split(prompt[i+len("DESCRIPTION:"):], "\n")[0])
	}
	return "```go\n" + fmt.Sprintf(`// Rule generated from: %s
package rule

// Detect flags users with more than 5 denied API calls in the window.
func Detect(events []Event) []Finding {
	denied := map[string]int{}
	for _, e := range events {
		if e.EventType == "api_call" && e.Status == "denied" && e.Username != "" {
			denied[e.Username]++
		}
	}
	var out []Finding
	for user, n := range denied {
		if n > 5 {
			out = append(out, Finding{
				Entity:   user,
				Title:    "Excessive denied API calls",
				Severity: "medium",
				Count:    n,
			})
		}
	}
	return out
}
`, strings.ReplaceAll(desc, "\n", " ")) + "```"
}
