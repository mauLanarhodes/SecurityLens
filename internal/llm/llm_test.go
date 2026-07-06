package llm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractJSON(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"a":1}`, `{"a":1}`},
		{"Here you go:\n```json\n{\"a\": {\"b\": 2}}\n```\nthanks", `{"a": {"b": 2}}`},
		{`prefix {"s":"braces } in { strings"} suffix`, `{"s":"braces } in { strings"}`},
		{`{"esc":"quote \" and brace }"}`, `{"esc":"quote \" and brace }"}`},
	}
	for _, c := range cases {
		if got := extractJSON(c.in); got != c.want {
			t.Errorf("extractJSON(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtractCode(t *testing.T) {
	in := "some prose\n```go\npackage rule\n```\ntrailer"
	if got := ExtractCode(in); got != "package rule" {
		t.Fatalf("got %q", got)
	}
	if got := ExtractCode("package rule"); got != "package rule" {
		t.Fatalf("no-fence passthrough failed: %q", got)
	}
}

// The mock must emit parseable JSON in the exact shape each feature parses,
// deterministically for the same input.
func TestMockShapesAndDeterminism(t *testing.T) {
	m := &Mock{}
	ctx := context.Background()

	tri1, _ := m.Complete(ctx, Request{Messages: []Message{{Role: "user",
		Content: "TASK: triage\nalert type credential_stuffing entity 1.2.3.4"}}})
	tri2, _ := m.Complete(ctx, Request{Messages: []Message{{Role: "user",
		Content: "TASK: triage\nalert type credential_stuffing entity 1.2.3.4"}}})
	if tri1.Text != tri2.Text {
		t.Fatal("mock triage not deterministic")
	}
	var tv struct {
		Verdict    string   `json:"verdict"`
		Confidence float64  `json:"confidence"`
		NextSteps  []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(extractJSON(tri1.Text)), &tv); err != nil {
		t.Fatalf("mock triage unparseable: %v", err)
	}
	if tv.Verdict == "" || tv.Confidence <= 0 || len(tv.NextSteps) == 0 {
		t.Fatalf("mock triage incomplete: %+v", tv)
	}

	inv, _ := m.Complete(ctx, Request{Messages: []Message{{Role: "user",
		Content: "TASK: investigate\nalert type lateral_movement"}}})
	var iv Investigation
	if err := json.Unmarshal([]byte(extractJSON(inv.Text)), &iv); err != nil {
		t.Fatalf("mock investigation unparseable: %v", err)
	}
	if iv.Hypothesis == "" || len(iv.PivotQueries) == 0 {
		t.Fatalf("mock investigation incomplete: %+v", iv)
	}
	if !strings.Contains(iv.Hypothesis, "lateral_movement") {
		t.Fatalf("mock should echo the alert type: %s", iv.Hypothesis)
	}

	rg, _ := m.Complete(ctx, Request{Messages: []Message{{Role: "user",
		Content: "TASK: rulegen\nDESCRIPTION: flag weird logins"}}})
	code := ExtractCode(rg.Text)
	if !strings.HasPrefix(code, "// Rule generated from: flag weird logins") {
		t.Fatalf("mock rule code missing description header:\n%s", code)
	}
	if !strings.Contains(code, "func Detect(events []Event) []Finding") {
		t.Fatalf("mock rule code missing Detect signature:\n%s", code)
	}
}
