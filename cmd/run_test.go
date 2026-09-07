package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
)

func TestIsGitURL(t *testing.T) {
	tests := []struct {
		source string
		want   bool
	}{
		{"https://github.com/foo/bar.git", true},
		{"https://github.com/foo/bar", true},
		{"http://example.com/repo", true},
		{"git://example.com/repo", true},
		{"ssh://git@example.com/repo.git", true},
		{"git@github.com:foo/bar.git", true},
		{"repo.git", true},
		{"./local/path", false},
		{"/abs/local/path", false},
		{"../relative", false},
		{"some-dir", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			if got := isGitURL(tt.source); got != tt.want {
				t.Errorf("isGitURL(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

func TestResolveRepoLocalPath(t *testing.T) {
	dir := t.TempDir()

	t.Run("existing directory resolves to abs path with noop cleanup", func(t *testing.T) {
		got, cleanup, err := resolveRepo(context.Background(), dir, io.Discard)
		if err != nil {
			t.Fatalf("resolveRepo error: %v", err)
		}
		cleanup() // must be safe to call
		want, _ := filepath.Abs(dir)
		if got != want {
			t.Errorf("dir = %q, want %q", got, want)
		}
	})

	t.Run("missing path errors", func(t *testing.T) {
		_, _, err := resolveRepo(context.Background(), filepath.Join(dir, "does-not-exist"), io.Discard)
		if err == nil {
			t.Fatal("expected error for missing path")
		}
	})

	t.Run("file that is not a directory errors", func(t *testing.T) {
		file := filepath.Join(dir, "afile")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := resolveRepo(context.Background(), file, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("error = %v, want it to mention 'not a directory'", err)
		}
	})
}

// The pre-run notice must state the active protections so the user sees the
// guarantees before anything runs.
func TestPrintPreRunNotice(t *testing.T) {
	var buf bytes.Buffer
	printPreRunNotice(&buf, "./repo", "", "node", sandbox.Profile{}.Normalize())
	out := buf.String()
	for _, want := range []string{
		"NEVER runs on the host",
		"NO host $HOME and NO repo bind mounts",
		"network DENIED",
		"force-removed",
		"ecosystem:        node",
		sandbox.DefaultImage,
		"docker (trust boundary)", // default runtime is surfaced
	} {
		if !strings.Contains(out, want) {
			t.Errorf("notice missing %q\n  got:\n%s", want, out)
		}
	}
}

// An explicit --runtime is echoed back in the notice so the user can see which
// runtime (the trust boundary) is enforcing the sandbox.
func TestPrintPreRunNoticeRuntime(t *testing.T) {
	var buf bytes.Buffer
	printPreRunNotice(&buf, "./repo", "podman", "node", sandbox.Profile{}.Normalize())
	if out := buf.String(); !strings.Contains(out, "podman (trust boundary)") {
		t.Errorf("notice did not surface the chosen runtime\n  got:\n%s", out)
	}
}

func TestPrintResult(t *testing.T) {
	var buf bytes.Buffer
	printResult(&buf, sandbox.Result{InstallExitCode: 5})
	out := buf.String()
	for _, want := range []string{
		"install exit code: 5",
		"0 host secrets exposed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("result missing %q\n  got:\n%s", want, out)
		}
	}
}
