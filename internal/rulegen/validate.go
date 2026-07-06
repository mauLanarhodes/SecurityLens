// Package rulegen validates LLM-generated detection rules. The LLM is treated
// as an untrusted code generator: its output is compiled in an isolated
// throwaway module with the network disabled and is NEVER executed. Only code
// that compiles cleanly is shown to the analyst for review.
package rulegen

import (
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// allowedImports is the allowlist for generated rules: pure computation only.
// Anything touching the OS, network, or process state is rejected before the
// compiler ever sees it — a "detection rule" has no business execing binaries.
var allowedImports = map[string]bool{
	"fmt": true, "strings": true, "strconv": true, "time": true, "sort": true,
	"math": true, "regexp": true, "unicode": true, "errors": true, "slices": true, "maps": true,
}

// checkImports parses the rule and rejects disallowed packages.
func checkImports(code string) error {
	f, err := parser.ParseFile(token.NewFileSet(), "rule.go", code, parser.ImportsOnly)
	if err != nil {
		return fmt.Errorf("parse: %v", err)
	}
	if f.Name.Name != "rule" {
		return fmt.Errorf("rule must declare `package rule`, got %q", f.Name.Name)
	}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if !allowedImports[path] {
			return fmt.Errorf("import %q is not allowed in generated rules", path)
		}
	}
	return nil
}

// goBinary resolves the go toolchain even when the server process's PATH
// doesn't include it (falls back to the GOROOT this binary was built with).
func goBinary() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	if g := runtime.GOROOT(); g != "" {
		if p := filepath.Join(g, "bin", "go"); fileExists(p) {
			return p
		}
	}
	return "go"
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// Result is the outcome of validating one generated rule.
type Result struct {
	Code           string `json:"code"`
	CompileOK      bool   `json:"compile_ok"`
	CompilerOutput string `json:"compiler_output,omitempty"`
}

// scaffold is the fixed part of the throwaway package the generated rule must
// compile against. It mirrors the operational fields of model.LogEvent without
// importing anything from SecurityLens, so the module is fully self-contained.
const scaffold = `package rule

import "time"

// Event mirrors the operational fields of a normalized log event.
type Event struct {
	TS        time.Time
	Source    string
	EventType string
	Username  string
	SrcIP     string
	DstHost   string
	Status    string
	BytesOut  int64
	Message   string
}

// Finding is one detection produced by a rule.
type Finding struct {
	Entity   string
	Title    string
	Severity string
	Count    int
}

// The generated file must provide exactly: func Detect(events []Event) []Finding
var _ func([]Event) []Finding = Detect
`

const goMod = "module ruleval\n\ngo 1.22\n"

// Validate compiles the generated code in an isolated module. It returns the
// compiler's verdict; it does not run the code.
func Validate(ctx context.Context, code string) (Result, error) {
	res := Result{Code: code}
	if strings.TrimSpace(code) == "" {
		res.CompilerOutput = "empty rule code"
		return res, nil
	}
	if err := checkImports(code); err != nil {
		res.CompilerOutput = err.Error()
		return res, nil
	}
	dir, err := os.MkdirTemp("", "securitylens-rulegen-*")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(dir)

	files := map[string]string{
		"go.mod":      goMod,
		"scaffold.go": scaffold,
		"rule.go":     code,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return res, err
		}
	}

	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, goBinary(), "build", "./...")
	cmd.Dir = dir
	// Isolated: no network module fetches, no shared build state surprises.
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=mod", "GO111MODULE=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.CompileOK = false
		res.CompilerOutput = strings.TrimSpace(string(out))
		if res.CompilerOutput == "" {
			res.CompilerOutput = fmt.Sprintf("compile failed: %v", err)
		}
		return res, nil
	}
	res.CompileOK = true
	return res, nil
}
