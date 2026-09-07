package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// DockerRunner is a Runner backed by the `docker` CLI, invoked via os/exec.
//
// It requires a Docker-compatible runtime on PATH, NOT Docker Desktop
// specifically. Docker, OrbStack (macOS), Colima (macOS/Linux), and Podman
// (daemonless, rootless) all satisfy it with no code change.
type DockerRunner struct {
	// Binary is the Docker-compatible CLI to invoke. Empty means "docker". Set
	// it to "podman" (or any compatible CLI) to switch runtimes.
	Binary string
}

func (d DockerRunner) bin() string {
	if d.Binary == "" {
		return "docker"
	}
	return d.Binary
}

// Preflight checks that a Docker-compatible runtime is reachable before meguard
// does any work (cloning, printing the run notice, creating a container). It
// runs `docker info` and, on failure, returns an actionable error naming the
// lightweight runtimes that satisfy the requirement. This turns the raw daemon
// connection error into guidance and avoids a misleading pre-run notice for a
// run that cannot start.
func (d DockerRunner) Preflight(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, d.bin(), "info")
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return runtimeUnavailableError(fmt.Errorf("%w: %s", err, msg))
		}
		return runtimeUnavailableError(err)
	}
	return nil
}

// runtimeUnavailableError wraps a preflight failure with actionable guidance. It
// keeps the underlying cause wrappable (errors.Is/As) while giving the user the
// list of Docker-compatible runtimes. Docker Desktop is never presented as the
// only option.
func runtimeUnavailableError(cause error) error {
	return fmt.Errorf(`no Docker-compatible runtime is available: %w

meguard needs a Docker-compatible runtime running on PATH (Docker Desktop is not required). Any of these work:
  - OrbStack (macOS, lightweight)
  - Colima  (macOS/Linux, lightweight)
  - Podman  (daemonless, rootless)
  - Docker Engine / Docker Desktop
Start your runtime, then check it with one of: orbstack status, colima status, podman info, docker info`, cause)
}

// Create runs `docker create` with the hardened argv and returns the container
// name, which meguard assigns so cleanup is deterministic even if stdout capture
// is empty.
func (d DockerRunner) Create(ctx context.Context, p Profile) (string, error) {
	name, err := containerName()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, d.bin(), createArgs(name, p)...)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard // docker prints the id; we use the name we assigned
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker create: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return name, nil
}

// CopyInto streams the CONTENTS of srcDir into destPath inside the container.
//
// It does NOT use `docker cp`: Docker refuses `docker cp` into a --read-only
// container (the rootfs read-only guard blocks it even for a tmpfs target).
// Instead meguard builds a deterministic tar stream in-process (see
// writeRepoTar) and pipes it to a `tar` process running inside the container via
// `docker exec -i`. That extractor writes to the tmpfs mount as the sandbox
// user; it is a process inside the container, so it is not subject to the
// read-only rootfs guard. This preserves the invariant that the repo lives in a
// container tmpfs with no host bind mount and no route to host secrets. The
// container image must provide `tar` (standard in Debian and Alpine bases).
//
// The container must be running before CopyInto is called.
func (d DockerRunner) CopyInto(ctx context.Context, id, srcDir, destPath string) error {
	pr, pw := io.Pipe()
	go func() {
		// Closing the writer with the build error propagates it to the reader,
		// which surfaces as a tar failure below.
		pw.CloseWithError(writeRepoTar(pw, srcDir))
	}()
	defer pr.Close()

	cmd := exec.CommandContext(ctx, d.bin(), tarExtractArgs(id, destPath)...)
	cmd.Stdin = pr
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stream repo into %s:%s via tar: %w: %s", id, destPath, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Start runs `docker start <id>`.
func (d DockerRunner) Start(ctx context.Context, id string) error {
	cmd := exec.CommandContext(ctx, d.bin(), "start", id)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker start %s: %w: %s", id, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Exec runs `docker exec <id> <cmd...>`, streaming output live. A non-zero exit
// code from the command is returned as exitCode with a nil error; only a failure
// to run docker itself is returned as an error.
func (d DockerRunner) Exec(ctx context.Context, id string, command []string, stdout, stderr io.Writer) (int, error) {
	args := append([]string{"exec", id}, command...)
	cmd := exec.CommandContext(ctx, d.bin(), args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// The command ran but exited non-zero. That is a repo/install outcome,
		// not a runner failure.
		return exitErr.ExitCode(), nil
	}
	return -1, fmt.Errorf("docker exec %s: %w", id, err)
}

// Remove runs `docker rm -f <id>`. It is safe to call with an empty id and safe
// to call more than once.
func (d DockerRunner) Remove(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, d.bin(), "rm", "-f", id)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker rm -f %s: %w: %s", id, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// containerName returns a unique, greppable container name.
func containerName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate container name: %w", err)
	}
	return "meguard-" + hex.EncodeToString(b[:]), nil
}
