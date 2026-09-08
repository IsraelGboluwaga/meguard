package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
)

// TestSubstituteCacheDir is table-driven over the number and position of
// CacheDirPlaceholder tokens in an argv: none, one, and more than one, plus a
// placeholder-lookalike that must NOT be substituted (only an exact token match
// counts).
func TestSubstituteCacheDir(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		cacheDir string
		want     []string
	}{
		{
			name:     "no placeholder leaves args untouched",
			args:     []string{"npm", "install", "--offline"},
			cacheDir: "/tmp/cache",
			want:     []string{"npm", "install", "--offline"},
		},
		{
			name:     "single placeholder is substituted",
			args:     []string{"npm", "install", "--cache", sandbox.CacheDirPlaceholder},
			cacheDir: "/tmp/cache",
			want:     []string{"npm", "install", "--cache", "/tmp/cache"},
		},
		{
			name:     "multiple placeholders are all substituted",
			args:     []string{sandbox.CacheDirPlaceholder, "--cache", sandbox.CacheDirPlaceholder},
			cacheDir: "/tmp/cache",
			want:     []string{"/tmp/cache", "--cache", "/tmp/cache"},
		},
		{
			name:     "a lookalike token that is not an exact match is untouched",
			args:     []string{"--cache", sandbox.CacheDirPlaceholder + "-suffix"},
			cacheDir: "/tmp/cache",
			want:     []string{"--cache", sandbox.CacheDirPlaceholder + "-suffix"},
		},
		{
			name:     "empty args returns empty",
			args:     []string{},
			cacheDir: "/tmp/cache",
			want:     []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := substituteCacheDir(tt.args, tt.cacheDir)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("substituteCacheDir(%v, %q) = %v, want %v", tt.args, tt.cacheDir, got, tt.want)
			}
		})
	}
}

// TestSubstituteCacheDirDoesNotMutateInput guards that substituteCacheDir
// returns a copy: mutating the result must not change the caller's original
// argv, since callers (runPrefetch) hold the ecosystem's shared PrefetchCmd
// slice.
func TestSubstituteCacheDirDoesNotMutateInput(t *testing.T) {
	original := []string{"npm", "install", "--cache", sandbox.CacheDirPlaceholder}
	snapshot := append([]string(nil), original...)

	got := substituteCacheDir(original, "/tmp/cache")
	got[0] = "mutated"

	if !reflect.DeepEqual(original, snapshot) {
		t.Errorf("input argv mutated: got %v, want unchanged %v", original, snapshot)
	}
}

// TestStageForMutationOwned asserts the owned=true (meguard-owned clone temp)
// path is a pure no-op: the same directory is returned, cleanup does nothing,
// and the directory is left in place afterward.
func TestStageForMutationOwned(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "file.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, cleanup, err := stageForMutation(repoDir, true)
	if err != nil {
		t.Fatalf("stageForMutation error: %v", err)
	}
	if got != repoDir {
		t.Errorf("stageForMutation(owned=true) = %q, want the same dir %q", got, repoDir)
	}

	cleanup()

	if _, err := os.Stat(repoDir); err != nil {
		t.Errorf("owned dir must survive cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "file.txt")); err != nil {
		t.Errorf("owned dir contents must survive cleanup: %v", err)
	}
}

// TestStageForMutationUnowned asserts the owned=false (user's own working tree)
// path copies the repo into a fresh temp dir, leaves the original untouched, and
// that cleanup removes the staged copy but not the original.
func TestStageForMutationUnowned(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "file.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repoDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "sub", "nested.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}

	staged, cleanup, err := stageForMutation(repoDir, false)
	if err != nil {
		t.Fatalf("stageForMutation error: %v", err)
	}
	if staged == repoDir {
		t.Fatal("stageForMutation(owned=false) must return a different dir than the original")
	}

	// The staged copy has the expected contents.
	got, err := os.ReadFile(filepath.Join(staged, "file.txt"))
	if err != nil || string(got) != "hi" {
		t.Errorf("staged file.txt = %q, %v, want %q, nil", got, err, "hi")
	}
	gotNested, err := os.ReadFile(filepath.Join(staged, "sub", "nested.txt"))
	if err != nil || string(gotNested) != "nested" {
		t.Errorf("staged sub/nested.txt = %q, %v, want %q, nil", gotNested, err, "nested")
	}

	// Mutate the staged copy to prove it is not the same directory as the
	// original: the original must be untouched by the mutation.
	if err := os.WriteFile(filepath.Join(staged, "file.txt"), []byte("mutated"), 0o644); err != nil {
		t.Fatal(err)
	}
	origContent, err := os.ReadFile(filepath.Join(repoDir, "file.txt"))
	if err != nil || string(origContent) != "hi" {
		t.Errorf("original file.txt = %q, %v, want untouched %q, nil", origContent, err, "hi")
	}

	cleanup()

	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("cleanup must remove the staged dir; stat err = %v", err)
	}
	if _, err := os.Stat(repoDir); err != nil {
		t.Errorf("cleanup must not touch the original dir: %v", err)
	}
}

// TestCopyDir is table-driven over the kinds of entries a staged repo copy must
// preserve: nested directories, regular files with their exact byte content and
// mode, and symlinks recreated (not followed).
func TestCopyDir(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	if err := os.WriteFile(filepath.Join(src, "top.txt"), []byte("top-level"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(src, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "nested", "inner.txt"), []byte("inner-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("top.txt", filepath.Join(src, "link-to-top.txt")); err != nil {
		t.Fatal(err)
	}

	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copyDir error: %v", err)
	}

	tests := []struct {
		name string
		rel  string
		want string
	}{
		{"top-level file", "top.txt", "top-level"},
		{"nested file", filepath.Join("nested", "inner.txt"), "inner-content"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := os.ReadFile(filepath.Join(dst, tt.rel))
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", tt.rel, err)
			}
			if string(got) != tt.want {
				t.Errorf("content of %s = %q, want %q", tt.rel, got, tt.want)
			}
		})
	}

	// The symlink must be recreated as a symlink pointing at the same target,
	// not followed and copied as a regular file.
	linkPath := filepath.Join(dst, "link-to-top.txt")
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Lstat(link-to-top.txt): %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("link-to-top.txt is not a symlink in the copy, mode = %v", info.Mode())
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink(link-to-top.txt): %v", err)
	}
	if target != "top.txt" {
		t.Errorf("symlink target = %q, want %q", target, "top.txt")
	}

	// The original source must be untouched by the copy.
	if _, err := os.Stat(filepath.Join(src, "top.txt")); err != nil {
		t.Errorf("source top.txt disturbed by copyDir: %v", err)
	}
}
