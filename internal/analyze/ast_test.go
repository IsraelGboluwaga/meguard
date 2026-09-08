package analyze

import "testing"

// TestASTAnalyzerIsLabeledNoop asserts the documented decision: the AST
// analyzer never silently reports a clean pass. Its reason must always be
// set, and it must never itself return findings in this build.
func TestASTAnalyzerIsLabeledNoop(t *testing.T) {
	a := newASTAnalyzer()
	if a.reason == "" {
		t.Fatal("AST analyzer must always state why it is disabled")
	}
	findings, err := a.Analyze(nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("noop AST analyzer must not produce findings, got %+v", findings)
	}
	if a.Name() != "ast" {
		t.Errorf("Name() = %q, want %q", a.Name(), "ast")
	}
}
