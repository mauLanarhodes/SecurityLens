package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"securitylens/internal/model"
)

// SensitiveDataExposure scans log messages for PII and secrets. The point of
// the classifier is discrimination: real credentials must alert while the
// documentation examples, placeholders, and masked values that saturate real
// logs must not — otherwise the LLM triage budget is burned on non-findings.
type SensitiveDataExposure struct{}

func (d *SensitiveDataExposure) Name() string { return "sensitive_data_exposure" }

// Finding is one classified secret occurrence.
type Finding struct {
	Kind     string // aws_key | api_secret | db_password | private_key | ssn | card
	Redacted string // safe-to-display fragment
}

var (
	reAWSKey  = regexp.MustCompile(`\bAKIA[A-Z0-9]{16}\b`)
	reKV      = regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|secret|token|passwd|password|access[_-]?key[_-]?id)\s*[=:]\s*([^\s,;"'=:]+)`)
	reStripe  = regexp.MustCompile(`\bsk_(live|test)_[A-Za-z0-9]{8,}\b`)
	reDBURI   = regexp.MustCompile(`\b(postgres|postgresql|mysql|mongodb)://[^:/\s]+:([^@\s]+)@`)
	rePrivKey = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	reSSN     = regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)
	reCard    = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
)

// placeholder tokens that mark a value as an example, not a live secret
var placeholderMarks = []string{
	"example", "sample", "placeholder", "redacted", "changeme", "change_me",
	"dummy", "your_", "xxxx", "yyyy", "zzzz", "<", ">", "${", "%s", "todo", "fixme",
	"**", // masked values
}

func looksPlaceholder(v string) bool {
	lv := strings.ToLower(v)
	for _, m := range placeholderMarks {
		if strings.Contains(lv, m) {
			return true
		}
	}
	// masked or trivially uniform values: ******, 000000, aaaa…
	uniform := true
	for i := 1; i < len(v); i++ {
		if v[i] != v[0] {
			uniform = false
			break
		}
	}
	if uniform && len(v) >= 4 {
		return true
	}
	return len(v) < 6
}

// looksLiveSecret: long enough and mixes character classes like real key material.
func looksLiveSecret(v string) bool {
	if len(v) < 8 || looksPlaceholder(v) {
		return false
	}
	var classes int
	for _, f := range []func(rune) bool{
		func(r rune) bool { return r >= 'a' && r <= 'z' },
		func(r rune) bool { return r >= 'A' && r <= 'Z' },
		func(r rune) bool { return r >= '0' && r <= '9' },
		func(r rune) bool { return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') },
	} {
		if strings.ContainsFunc(v, f) {
			classes++
		}
	}
	return classes >= 2
}

func redact(v string) string {
	if len(v) <= 8 {
		return "****"
	}
	return v[:4] + strings.Repeat("*", 6) + v[len(v)-2:]
}

// ClassifyMessage returns the secrets found in one log message.
func ClassifyMessage(msg string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	add := func(kind, raw string) {
		k := kind + "|" + raw
		if !seen[k] {
			seen[k] = true
			out = append(out, Finding{Kind: kind, Redacted: redact(raw)})
		}
	}

	for _, m := range reAWSKey.FindAllString(msg, -1) {
		if !strings.Contains(m, "EXAMPLE") {
			add("aws_key", m)
		}
	}
	for _, m := range reStripe.FindAllStringSubmatch(msg, -1) {
		if m[1] == "live" && !looksPlaceholder(m[0][len("sk_live_"):]) {
			add("api_secret", m[0])
		}
	}
	for _, m := range reDBURI.FindAllStringSubmatch(msg, -1) {
		if looksLiveSecret(m[2]) {
			add("db_password", m[2])
		}
	}
	if rePrivKey.MatchString(msg) {
		add("private_key", "PRIVATE KEY block")
	}
	for _, m := range reKV.FindAllStringSubmatch(msg, -1) {
		v := m[2]
		// skip values other rules already classified (AKIA…, sk_live_…, URIs)
		if reAWSKey.MatchString(v) || reStripe.MatchString(v) || strings.Contains(v, "://") {
			continue
		}
		if looksLiveSecret(v) {
			add("api_secret", v)
		}
	}
	for _, m := range reSSN.FindAllStringSubmatch(msg, -1) {
		if m[1] == "000" || m[1] == "666" || m[1] >= "900" || (m[1] == "123" && m[2] == "45" && m[3] == "6789") {
			continue
		}
		add("ssn", m[0])
	}
	for _, m := range reCard.FindAllString(msg, -1) {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, m)
		if len(digits) < 13 || len(digits) > 19 || !luhnOK(digits) {
			continue
		}
		if isTestCard(digits) {
			continue
		}
		add("card", digits)
	}
	return out
}

func luhnOK(digits string) bool {
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

var testCards = map[string]bool{
	"4111111111111111": true, "4242424242424242": true, "5555555555554444": true,
	"378282246310005": true, "6011111111111117": true, "4012888888881881": true,
}

func isTestCard(d string) bool { return testCards[d] }

func (d *SensitiveDataExposure) Detect(w Window, events []model.LogEvent, _ *BaselineView) []model.Candidate {
	type agg struct {
		evs   []model.LogEvent
		kinds map[string]int64
	}
	byUser := map[string]*agg{}
	for _, e := range events {
		if e.Message == "" {
			continue
		}
		fs := ClassifyMessage(e.Message)
		if len(fs) == 0 {
			continue
		}
		key := e.Username
		if key == "" {
			key = e.DstHost
		}
		if key == "" {
			key = e.SrcIP
		}
		a := byUser[key]
		if a == nil {
			a = &agg{kinds: map[string]int64{}}
			byUser[key] = a
		}
		a.evs = append(a.evs, e)
		for _, f := range fs {
			a.kinds[f.Kind]++
		}
	}
	var out []model.Candidate
	for u, a := range byUser {
		start, end := span(a.evs)
		kinds := make([]string, 0, len(a.kinds))
		for k := range a.kinds {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		out = append(out, model.Candidate{
			AlertType: model.TypeSensitiveDataExposure,
			Severity:  model.SevHigh,
			Entity:    u,
			Username:  a.evs[0].Username,
			SrcIP:     a.evs[0].SrcIP,
			Title:     fmt.Sprintf("Sensitive data exposure: live secrets in logs attributed to %s (%s)", u, strings.Join(kinds, ", ")),
			EvStart:   start, EvEnd: end,
			Evidence: model.Evidence{
				Counts:  a.kinds,
				Notes:   []string{"values matched live-secret patterns and are not documentation placeholders"},
				Samples: redactSamples(sampleEvents(a.evs, 5)),
			},
		})
	}
	sortCands(out)
	return out
}

// redactSamples masks secret material so the alert itself never re-leaks it.
func redactSamples(evs []model.LogEvent) []model.LogEvent {
	for i := range evs {
		evs[i].Message = RedactMessage(evs[i].Message)
	}
	return evs
}

// RedactMessage masks every live secret found in msg.
func RedactMessage(msg string) string {
	for _, re := range []*regexp.Regexp{reAWSKey, reStripe} {
		msg = re.ReplaceAllStringFunc(msg, func(m string) string {
			if strings.Contains(m, "EXAMPLE") || strings.Contains(m, "sk_test_") {
				return m
			}
			return redact(m)
		})
	}
	msg = reDBURI.ReplaceAllString(msg, "$1://****:****@")
	msg = reKV.ReplaceAllStringFunc(msg, func(m string) string {
		sub := reKV.FindStringSubmatch(m)
		if looksLiveSecret(sub[2]) {
			return sub[1] + "=" + redact(sub[2])
		}
		return m
	})
	return msg
}
