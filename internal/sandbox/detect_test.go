package sandbox

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestDetectEcosystem is a table-driven test of manifest-to-ecosystem mapping.
// Each case lays down marker files in a temp repo root and asserts the detected
// ecosystem, the resolved image, and the install command. It also pins the
// precedence rules: Node over Python for a polyglot repo, and requirements.txt
// over a project manifest within Python.
func TestDetectEcosystem(t *testing.T) {
	tests := []struct {
		name      string
		files     []string
		wantOK    bool
		wantName  string
		wantImage string
		wantCmd   []string
	}{
		{
			name:      "package.json is node",
			files:     []string{"package.json"},
			wantOK:    true,
			wantName:  "node",
			wantImage: DefaultImage,
			wantCmd:   DefaultInstallCmd(),
		},
		{
			name:      "lockfile alone is node",
			files:     []string{"pnpm-lock.yaml"},
			wantOK:    true,
			wantName:  "node",
			wantImage: DefaultImage,
			wantCmd:   DefaultInstallCmd(),
		},
		{
			name:      "requirements.txt is python with -r install",
			files:     []string{"requirements.txt"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "-r", "requirements.txt"},
		},
		{
			name:      "pyproject.toml is python with project install",
			files:     []string{"pyproject.toml"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "."},
		},
		{
			name:      "setup.py is python with project install",
			files:     []string{"setup.py"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "."},
		},
		{
			name:      "requirements.txt wins over pyproject.toml",
			files:     []string{"pyproject.toml", "requirements.txt"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "-r", "requirements.txt"},
		},
		{
			name:      "node wins over python in a polyglot repo",
			files:     []string{"package.json", "requirements.txt"},
			wantOK:    true,
			wantName:  "node",
			wantImage: DefaultImage,
			wantCmd:   DefaultInstallCmd(),
		},
		{
			name:   "no manifest is not detected",
			files:  []string{"README.md", "main.go"},
			wantOK: false,
		},
		{
			name:   "empty repo is not detected",
			files:  nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for _, f := range tt.files {
				if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			eco, ok := DetectEcosystem(root)
			if ok != tt.wantOK {
				t.Fatalf("DetectEcosystem ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if eco.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", eco.Name, tt.wantName)
			}
			if eco.Image != tt.wantImage {
				t.Errorf("Image = %q, want %q", eco.Image, tt.wantImage)
			}
			if !reflect.DeepEqual(eco.InstallCmd, tt.wantCmd) {
				t.Errorf("InstallCmd = %v, want %v", eco.InstallCmd, tt.wantCmd)
			}
		})
	}
}

// A directory named like a manifest must not be mistaken for one: detection
// keys off regular files.
func TestDetectEcosystemIgnoresDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "package.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := DetectEcosystem(root); ok {
		t.Fatal("a directory named package.json must not be detected as an ecosystem")
	}
}
