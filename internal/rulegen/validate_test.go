package rulegen

import (
	"context"
	"os"
	"strings"
	"testing"
)

const goodRule = `package rule

func Detect(events []Event) []Finding {
	var out []Finding
	for _, e := range events {
		if e.Status == "denied" {
			out = append(out, Finding{Entity: e.Username, Title: "denied op", Severity: "low", Count: 1})
		}
	}
	return out
}
`

func TestValidateCompilesGoodRule(t *testing.T) {
	res, err := Validate(context.Background(), goodRule)
	if err != nil {
		t.Fatal(err)
	}
	if !res.CompileOK {
		t.Fatalf("good rule rejected: %s", res.CompilerOutput)
	}
}

func TestValidateRejectsBrokenCode(t *testing.T) {
	cases := map[string]string{
		"syntax error":     "package rule\nfunc Detect(events []Event []Finding {",
		"missing Detect":   "package rule\nfunc NotDetect() {}",
		"wrong signature":  "package rule\nfunc Detect(x int) int { return x }",
		"forbidden import": "package rule\nimport \"os/exec\"\nfunc Detect(events []Event) []Finding { _ = exec.Command; return nil }",
		"empty":            "   ",
	}
	for name, code := range cases {
		res, err := Validate(context.Background(), code)
		if err != nil {
			t.Fatalf("%s: infra error: %v", name, err)
		}
		if res.CompileOK {
			t.Errorf("%s: broken code accepted", name)
		}
		if res.CompilerOutput == "" {
			t.Errorf("%s: no compiler output for analyst review", name)
		}
	}
}

func TestValidateNeverExecutes(t *testing.T) {
	// A rule whose init() would create a file if it ever ran. Two layers must
	// hold: the import allowlist rejects "os" outright, and even code that
	// passes validation is only compiled, never run.
	evil := `package rule

import "os"

func init() { os.WriteFile("/tmp/securitylens-rulegen-EXECUTED", []byte("x"), 0o644) }

func Detect(events []Event) []Finding { return nil }
`
	res, err := Validate(context.Background(), evil)
	if err != nil {
		t.Fatal(err)
	}
	if res.CompileOK {
		t.Fatal("os-importing rule should be rejected by the import allowlist")
	}
	if !strings.Contains(res.CompilerOutput, `"os" is not allowed`) {
		t.Fatalf("expected allowlist rejection, got: %s", res.CompilerOutput)
	}
	if _, err := os.Stat("/tmp/securitylens-rulegen-EXECUTED"); err == nil {
		t.Fatal("generated code was EXECUTED during validation")
	}

	// benign init() side effects compile but still never run
	sneaky := `package rule

var executed = sideEffect()

func sideEffect() bool { panic("this must never run") }

func Detect(events []Event) []Finding { return nil }
`
	res2, err := Validate(context.Background(), sneaky)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.CompileOK {
		t.Fatalf("sneaky rule should compile: %s", res2.CompilerOutput)
	}
}

func TestValidateRejectsSelfDeclaredTypes(t *testing.T) {
	dup := "package rule\ntype Event struct{}\nfunc Detect(events []Event) []Finding { return nil }"
	res, _ := Validate(context.Background(), dup)
	if res.CompileOK {
		t.Fatal("re-declared scaffold type should fail compilation")
	}
	if !strings.Contains(res.CompilerOutput, "redeclared") && !strings.Contains(res.CompilerOutput, "Finding") {
		t.Logf("compiler output: %s", res.CompilerOutput)
	}
}
