package analyze

import (
	"strings"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		wantLow bool // true if entropy should be well below highEntropyThreshold
	}{
		{"empty", "", true},
		{"single repeated char", strings.Repeat("a", 100), true},
		{"english prose", strings.Repeat("the quick brown fox jumps over the lazy dog ", 5), true},
		{"random-looking base64", "aGVsbG8gd29ybGQhIHRoaXMgaXMgc29tZSByYW5kb20gbG9va2luZyBiYXNlNjQgZGF0YQ==", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.s)
			if tt.wantLow && got >= highEntropyThreshold {
				t.Errorf("shannonEntropy(%q) = %.2f, expected below %.2f", tt.name, got, highEntropyThreshold)
			}
			if !tt.wantLow && got < 3.0 {
				t.Errorf("shannonEntropy(%q) = %.2f, expected reasonably high", tt.name, got)
			}
		})
	}
}

func TestEntropyAnalyzerIgnoresShortLines(t *testing.T) {
	files := []ScannedFile{{
		RelPath: "a.js",
		Content: "const x = 1;\n",
		Lines:   []string{"const x = 1;", ""},
	}}
	findings, err := entropyAnalyzer{}.Analyze(files)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for short lines, got %+v", findings)
	}
}

func TestEntropyAnalyzerFlagsLongDenseLine(t *testing.T) {
	long := strings.Repeat("aGVsbG8gd29ybGQhIHRoaXMgaXMgc29tZSByYW5kb20gbG9va2luZyBkYXRh", 10)
	files := []ScannedFile{{
		RelPath: "a.js",
		Content: long,
		Lines:   []string{long},
	}}
	findings, err := entropyAnalyzer{}.Analyze(files)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity < Medium {
		t.Errorf("expected at least Medium severity, got %s", findings[0].Severity)
	}
}
