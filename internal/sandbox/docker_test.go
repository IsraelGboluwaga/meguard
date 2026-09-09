package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerRunnerBinDefault(t *testing.T) {
	tests := []struct {
		name   string
		runner DockerRunner
		want   string
	}{
		{"zero value defaults to docker", DockerRunner{}, "docker"},
		{"explicit podman", DockerRunner{Binary: "podman"}, "podman"},
		{"explicit nerdctl", DockerRunner{Binary: "nerdctl"}, "nerdctl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.runner.bin(); got != tt.want {
				t.Errorf("bin() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestContainerName(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		name, err := containerName()
		if err != nil {
			t.Fatalf("containerName error: %v", err)
		}
		if !strings.HasPrefix(name, "meguard-") {
			t.Errorf("name %q missing meguard- prefix", name)
		}
		// 8 random bytes -> 16 hex chars after the prefix.
		if hex := strings.TrimPrefix(name, "meguard-"); len(hex) != 16 {
			t.Errorf("name %q hex part = %d chars, want 16", name, len(hex))
		}
		if seen[name] {
			t.Errorf("duplicate container name %q", name)
		}
		seen[name] = true
	}
}

// fakeDockerBin writes an executable stub script to a temp dir and returns its
// path. The script fails the `create` subcommand and, for any other subcommand,
// appends its full argv to recordFile and succeeds. It lets a test drive
// DockerRunner without a real Docker daemon.
func fakeDockerBin(t *testing.T, recordFile string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-docker")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = create ]; then echo 'boom' 1>&2; exit 1; fi\n" +
		"echo \"$@\" >> " + recordFile + "\n" +
		"exit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	return path
}

// Create must not leak a container when `docker create` fails: the daemon may
// have created the container even though the CLI errored, and the caller only
// registers its cleanup defer once Create returns a non-empty id. So Create
// itself force-removes the container by the name it assigned before returning
// the error (invariant 5: cleanup on every path).
func TestCreateRemovesContainerOnFailure(t *testing.T) {
	recordFile := filepath.Join(t.TempDir(), "calls.log")
	runner := DockerRunner{Binary: fakeDockerBin(t, recordFile)}

	id, err := runner.Create(context.Background(), Profile{})
	if err == nil {
		t.Fatal("Create returned nil error though `docker create` failed")
	}
	if id != "" {
		t.Errorf("Create returned id %q on failure, want empty", id)
	}

	data, readErr := os.ReadFile(recordFile)
	if readErr != nil {
		t.Fatalf("Create did not invoke cleanup: %v", readErr)
	}
	got := strings.TrimSpace(string(data))
	// The cleanup call must be a force-remove of a meguard- container.
	if !strings.HasPrefix(got, "rm -f meguard-") {
		t.Errorf("cleanup call = %q, want `rm -f meguard-...`", got)
	}
}

// runtimeUnavailableError must wrap the cause (so errors.Is works) and give
// actionable, runtime-agnostic guidance that never presents Docker Desktop as
// the only option.
func TestRuntimeUnavailableError(t *testing.T) {
	cause := errors.New("dial unix: connect: no such file or directory")
	err := runtimeUnavailableError(cause)

	if !errors.Is(err, cause) {
		t.Errorf("runtimeUnavailableError does not wrap its cause")
	}
	msg := err.Error()
	for _, want := range []string{
		"Docker Desktop is not required",
		"OrbStack",
		"Colima",
		"Podman",
		"docker info",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("guidance missing %q\n  got: %s", want, msg)
		}
	}
}
