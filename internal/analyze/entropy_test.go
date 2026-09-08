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

func TestEntropyAnalyzerExcludesSVGPathData(t *testing.T) {
	// Real SVG icons legitimately carry one long line of path coordinates
	// (M/L/C/Z commands, digits, commas) that reads as long and moderately
	// high entropy without being an obfuscated payload.
	long := strings.Repeat("M12.5,3.2 L45.1,88.7 C10.2,20.5 30.9,40.1 50.0,60.0 Z ", 20)
	files := []ScannedFile{{
		RelPath: "public/icon.svg",
		Content: long,
		Lines:   []string{long},
	}}
	findings, err := entropyAnalyzer{}.Analyze(files)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no entropy findings for .svg path data, got %+v", findings)
	}
}

func TestEntropyAnalyzerScansSVGWithScriptTag(t *testing.T) {
	// An SVG carrying a <script> tag is executable, not static vector
	// graphics, so it must lose the path-data exclusion above and still be
	// scrutinized like any other code.
	longObfuscated := "var _payload = \"" + strings.Repeat("aGVsbG8gd29ybGQhIHRoaXMgaXMgc29tZSByYW5kb20gbG9va2luZyBkYXRh", 10) + "\";"
	content := "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>" + longObfuscated + "</script></svg>"
	files := []ScannedFile{{
		RelPath: "public/evil.svg",
		Content: content,
		Lines:   []string{content},
	}}
	findings, err := entropyAnalyzer{}.Analyze(files)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the script-carrying SVG's long line to still be flagged, got %d findings: %+v", len(findings), findings)
	}
}
