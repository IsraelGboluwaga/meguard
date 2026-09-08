package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalkFilesSkipsNoiseDirs(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"index.js":                  "console.log(1);\n",
		"main.py":                   "print(1)\n",
		"node_modules/pkg/index.js": "console.log(2);\n",
		".git/HEAD":                 "ref: refs/heads/main\n",
		"dist/bundle.min.js":        "var a=1;\n",
		// Python dependency trees and inert tool caches: same tier as
		// node_modules (see skipDirNames), must be skipped.
		"env/lib/site-packages/p.py":    "print(2)\n",
		".tox/py311/lib/pkg.py":         "print(3)\n",
		".eggs/dep-1.0.egg/mod.py":      "print(4)\n",
		".mypy_cache/3.11/x.data.json":  "{}\n",
		".pytest_cache/v/cache/nodeids": "[]\n",
		// Generated packaging metadata dirs (glob-named, matched by suffix).
		"proj.egg-info/PKG-INFO": "Name: proj\n",
		"proj.dist-info/RECORD":  "proj/__init__.py,,\n",
	})

	files, _, err := walkFiles(root)
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}

	var paths []string
	for _, f := range files {
		paths = append(paths, f.RelPath)
	}

	for _, want := range []string{"index.js", "main.py", "dist/bundle.min.js"} {
		found := false
		for _, p := range paths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s to be scanned, got %v", want, paths)
		}
	}
	for _, unwanted := range []string{
		"node_modules/pkg/index.js",
		".git/HEAD",
		"env/lib/site-packages/p.py",
		".tox/py311/lib/pkg.py",
		".eggs/dep-1.0.egg/mod.py",
		".mypy_cache/3.11/x.data.json",
		".pytest_cache/v/cache/nodeids",
		"proj.egg-info/PKG-INFO",
		"proj.dist-info/RECORD",
	} {
		for _, p := range paths {
			if p == unwanted {
				t.Errorf("expected %s to be skipped, but it was scanned", unwanted)
			}
		}
	}
}

func TestIsGeneratedMetadataDir(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"proj.egg-info", true},
		{"my_pkg-1.2.3.dist-info", true},
		{"egg-info", false}, // no package-name prefix / not a suffix boundary
		{"src", false},
		{"info", false},
	}
	for _, tt := range tests {
		if got := isGeneratedMetadataDir(tt.name); got != tt.want {
			t.Errorf("isGeneratedMetadataDir(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWalkFilesSkipsBinaryAndOversized(t *testing.T) {
	root := t.TempDir()
	binPath := filepath.Join(root, "photo.bin")
	if err := os.WriteFile(binPath, []byte("PNG\x00\x01\x02binarydata"), 0o644); err != nil {
		t.Fatal(err)
	}
	bigPath := filepath.Join(root, "big.txt")
	big := make([]byte, maxScanFileSize+1)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(bigPath, big, 0o644); err != nil {
		t.Fatal(err)
	}

	files, _, err := walkFiles(root)
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected binary and oversized files to be skipped, got %v", files)
	}
}

// TestWalkFilesSkipsSymlinks is a security-relevant regression test: a
// malicious repo could otherwise plant a symlink pointing outside the repo
// (for example at a host credential file) to trick scan into reading it.
// walkFiles must never dereference a symlink, whether it points to a file or
// a directory.
func TestWalkFilesSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	secretFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("host secret, must never be read"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretFile, filepath.Join(root, "link-to-secret.txt")); err != nil {
		t.Fatal(err)
	}

	outsideDir := filepath.Join(outside, "dir")
	if err := os.Mkdir(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "also-secret.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(root, "link-to-dir")); err != nil {
		t.Fatal(err)
	}

	files, _, err := walkFiles(root)
	if err != nil {
		t.Fatalf("walkFiles: %v", err)
	}
	for _, f := range files {
		if f.RelPath == "link-to-secret.txt" {
			t.Errorf("walkFiles must not dereference a symlinked file, got content: %q", f.Content)
		}
		if strings.Contains(f.RelPath, "also-secret") {
			t.Errorf("walkFiles must not descend into a symlinked directory, got %s", f.RelPath)
		}
	}
}

func TestWalkFilesMissingRootErrors(t *testing.T) {
	_, _, err := walkFiles(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("expected an error for a missing repo dir")
	}
}

func TestIsMinifiedOrVendorPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"src/index.js", false},
		{"vendor.min.js", true},
		{"app.bundle.js", true},
		{"dist/app.js", true},
		{"build/output.js", true},
		{"src/dist-utils.js", false}, // "dist" only matches as a full path segment
	}
	for _, tt := range tests {
		if got := isMinifiedOrVendorPath(tt.path); got != tt.want {
			t.Errorf("isMinifiedOrVendorPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestLooksBinary(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"plain text", []byte("hello world"), false},
		{"nul byte", []byte("hello\x00world"), true},
		{"empty", []byte(""), false},
	}
	for _, tt := range tests {
		if got := looksBinary(tt.data); got != tt.want {
			t.Errorf("looksBinary(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
