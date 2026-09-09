package sandbox

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// nodeInstallCmd and nodePrefetchCmd/nodeOfflineInstallCmd mirror the literal
// values detectNode sets, so this test fails the moment detectNode's argv
// drifts from what the sandbox two-phase install actually expects.
var (
	nodeInstallCmd        = []string{"npm", "install", "--no-audit", "--no-fund", "--fetch-retries=0"}
	nodePrefetchCmd       = []string{"npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org/", "--cache", CacheDirPlaceholder}
	nodeOfflineInstallCmd = []string{"npm", "install", "--offline", "--no-audit", "--no-fund", "--cache", ContainerCacheDir}
)

// TestDetectEcosystem is a table-driven test of manifest-to-ecosystem mapping.
// Each case lays down marker files in a temp repo root and asserts the detected
// ecosystem, the resolved image, and the install command. It also pins the
// precedence rules: Node over Python for a polyglot repo, and requirements.txt
// over a project manifest within Python. It also pins the two-phase fields:
// node gets a PrefetchCmd and OfflineInstallCmd, python gets neither (single-
// phase by design; see detectPython's comment on why pip cannot be given one).
func TestDetectEcosystem(t *testing.T) {
	tests := []struct {
		name           string
		files          []string
		wantOK         bool
		wantName       string
		wantImage      string
		wantCmd        []string
		wantPrefetch   []string
		wantOfflineCmd []string
	}{
		{
			name:           "package.json is node",
			files:          []string{"package.json"},
			wantOK:         true,
			wantName:       "node",
			wantImage:      DefaultImage,
			wantCmd:        nodeInstallCmd,
			wantPrefetch:   nodePrefetchCmd,
			wantOfflineCmd: nodeOfflineInstallCmd,
		},
		{
			name:           "lockfile alone is node",
			files:          []string{"pnpm-lock.yaml"},
			wantOK:         true,
			wantName:       "node",
			wantImage:      DefaultImage,
			wantCmd:        nodeInstallCmd,
			wantPrefetch:   nodePrefetchCmd,
			wantOfflineCmd: nodeOfflineInstallCmd,
		},
		{
			name:      "requirements.txt is python with -r install",
			files:     []string{"requirements.txt"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "--retries", "0", "--timeout", "5", "-r", "requirements.txt"},
		},
		{
			name:      "pyproject.toml is python with project install",
			files:     []string{"pyproject.toml"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "--retries", "0", "--timeout", "5", "."},
		},
		{
			name:      "setup.py is python with project install",
			files:     []string{"setup.py"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "--retries", "0", "--timeout", "5", "."},
		},
		{
			name:      "requirements.txt wins over pyproject.toml",
			files:     []string{"pyproject.toml", "requirements.txt"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "--retries", "0", "--timeout", "5", "-r", "requirements.txt"},
		},
		{
			name:           "node wins over python in a polyglot repo",
			files:          []string{"package.json", "requirements.txt"},
			wantOK:         true,
			wantName:       "node",
			wantImage:      DefaultImage,
			wantCmd:        nodeInstallCmd,
			wantPrefetch:   nodePrefetchCmd,
			wantOfflineCmd: nodeOfflineInstallCmd,
		},
		{
			name:      "loose .py with no manifest is python with a no-op install",
			files:     []string{"apalara.py", "README.md"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"python", "--version"},
		},
		{
			name:      "manifest wins over loose .py",
			files:     []string{"requirements.txt", "app.py"},
			wantOK:    true,
			wantName:  "python",
			wantImage: "python:3.12-slim",
			wantCmd:   []string{"pip", "install", "--user", "--retries", "0", "--timeout", "5", "-r", "requirements.txt"},
		},
		{
			name:           "node wins over a loose .py",
			files:          []string{"package.json", "app.py"},
			wantOK:         true,
			wantName:       "node",
			wantImage:      DefaultImage,
			wantCmd:        nodeInstallCmd,
			wantPrefetch:   nodePrefetchCmd,
			wantOfflineCmd: nodeOfflineInstallCmd,
		},
		{
			name:   "no manifest and no .py is not detected",
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
			if !reflect.DeepEqual(eco.PrefetchCmd, tt.wantPrefetch) {
				t.Errorf("PrefetchCmd = %v, want %v", eco.PrefetchCmd, tt.wantPrefetch)
			}
			if !reflect.DeepEqual(eco.OfflineInstallCmd, tt.wantOfflineCmd) {
				t.Errorf("OfflineInstallCmd = %v, want %v", eco.OfflineInstallCmd, tt.wantOfflineCmd)
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
