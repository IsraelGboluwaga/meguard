package sandbox

import (
	"errors"
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
