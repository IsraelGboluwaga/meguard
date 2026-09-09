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
	"time"
)

// Compile-time assertion that DockerRunner provides egress inspection.
var _ EgressInspector = DockerRunner{}

// monitorReadyTimeout bounds how long StartMonitor waits for the monitor to
// install its sinkhole and print the readiness marker. If it is not ready in
// time the monitor is torn down and the run fails closed: the sandbox is never
// created, so it can never join a netns whose egress is not yet sealed.
const monitorReadyTimeout = 20 * time.Second

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
		// `docker create` can fail the CLI invocation (e.g. ctx cancelled at the
		// boundary) after the daemon has already created the container. The
		// caller only registers its cleanup defer once Create returns a non-empty
		// id, so remove the container by the name we assigned here, best-effort on
		// a detached context, before returning. `docker rm -f` on a name that was
		// never created is a harmless no-op (invariant 5: cleanup on every path).
		removeDetached(d, name, io.Discard)
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

// StartMonitor creates and starts the egress monitor sidecar, then BLOCKS until
// the monitor has installed its sinkhole and printed the readiness marker. Only
// then does it return the monitor's name for the sandbox to join. If readiness
// does not arrive within monitorReadyTimeout the monitor is force-removed and an
// error is returned, so the caller never creates a sandbox against a netns whose
// egress is not yet sealed (fail closed).
//
// SAFETY INVARIANT 4/5: on any failure here the monitor this method created is
// removed before returning, so a partial start never leaks a container.
func (d DockerRunner) StartMonitor(ctx context.Context, p Profile) (string, error) {
	name, err := containerName()
	if err != nil {
		return "", err
	}
	name = "meguard-egress-" + strings.TrimPrefix(name, "meguard-")

	cleanup := func() {
		rmCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		_ = d.Remove(rmCtx, name)
	}

	create := exec.CommandContext(ctx, d.bin(), monitorCreateArgs(name, p)...)
	create.Stdout = io.Discard
	var cErr bytes.Buffer
	create.Stderr = &cErr
	if err := create.Run(); err != nil {
		return "", fmt.Errorf("docker create egress monitor: %w: %s", err, strings.TrimSpace(cErr.String()))
	}
	if err := d.Start(ctx, name); err != nil {
		cleanup()
		return "", err
	}
	if err := d.waitForMonitorReady(ctx, name); err != nil {
		cleanup()
		return "", err
	}
	return name, nil
}

// waitForMonitorReady polls the monitor's logs until the readiness marker
// appears (the netns seal is verified in-container) or the timeout elapses. If
// the monitor process exits before printing the marker, the seal script aborted
// (fail closed): this is detected and reported immediately rather than waited
// out, so a sandbox is never created against a monitor that failed to seal.
func (d DockerRunner) waitForMonitorReady(ctx context.Context, name string) error {
	deadline := time.Now().Add(monitorReadyTimeout)
	for {
		out, err := d.captureLogs(ctx, name)
		if err == nil && strings.Contains(out, monitorReadyMarker) {
			return nil
		}
		// Fail fast if the monitor already exited without sealing: the readiness
		// marker will never come, so do not wait for the full timeout.
		if d.containerExited(ctx, name) && !strings.Contains(out, monitorReadyMarker) {
			return fmt.Errorf("egress monitor exited before sealing the network (fail closed): %s", strings.TrimSpace(out))
		}
		if time.Now().After(deadline) {
			detail := strings.TrimSpace(out)
			if detail == "" && err != nil {
				detail = err.Error()
			}
			return fmt.Errorf("egress monitor did not become ready within %s: %s", monitorReadyTimeout, detail)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// containerExited reports whether the named container is no longer running. It
// is best-effort: on any inspect error it returns false so the caller falls back
// to the readiness timeout rather than misreporting a live monitor as exited.
func (d DockerRunner) containerExited(ctx context.Context, name string) bool {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, d.bin(), "inspect", "-f", "{{.State.Running}}", name)
	cmd.Stdout = &buf
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return false
	}
	return strings.TrimSpace(buf.String()) == "false"
}

// CollectEgress reads the monitor's captured output and returns the
// deduplicated, ordered list of blocked outbound attempts.
func (d DockerRunner) CollectEgress(ctx context.Context, name string) ([]EgressEvent, error) {
	out, err := d.captureLogs(ctx, name)
	if err != nil {
		return nil, err
	}
	return parseEgress(out), nil
}

// captureLogs runs `docker logs <name>` and returns its combined output.
// tcpdump writes captured lines to stdout and its banner to stderr; both are
// wanted, and parseEgress ignores anything that is not a capture line.
func (d DockerRunner) captureLogs(ctx context.Context, name string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, d.bin(), monitorLogsArgs(name)...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return buf.String(), fmt.Errorf("docker logs %s: %w", name, err)
	}
	return buf.String(), nil
}

// containerName returns a unique, greppable container name.
func containerName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate container name: %w", err)
	}
	return "meguard-" + hex.EncodeToString(b[:]), nil
}
