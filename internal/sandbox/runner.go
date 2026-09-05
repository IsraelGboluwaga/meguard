// Package sandbox creates and drives locked-down container sandboxes for
// executing untrusted repositories.
//
// SAFETY: this package NEVER imports internal/analyze or any analyzer package.
// The run path's guarantee is independent of scan, and that separation is
// enforced structurally by TestSandboxDoesNotImportAnalyze.
package sandbox

import (
	"context"
	"io"
)

// Runner drives the lifecycle of a single locked-down sandbox container.
//
// TRUST BOUNDARY: the container daemon (dockerd or a Docker-compatible runtime)
// runs with elevated privileges and is a trust boundary. meguard trusts the
// runtime to enforce the isolation configured at Create time; it does not trust
// the repo code that runs inside the container.
//
// The only implementation in this slice is DockerRunner, which shells out to
// the `docker` CLI via os/exec. This works unchanged against any
// Docker-compatible runtime on PATH: Docker, OrbStack, Colima, or Podman.
//
// UPGRADE PATHS (documented so future work inherits the decision):
//   - If parsing CLI output becomes fragile, move to the Docker Go SDK.
//   - Future Runner backends, in preference order for a security tool:
//     1. Podman rootless  - removes the root-daemon trust boundary
//     2. gVisor (runsc)   - user-space kernel, stronger syscall isolation
//     3. Firecracker      - microVM, strongest kernel boundary
type Runner interface {
	// Create builds a stopped, hardened container from p and returns its id.
	Create(ctx context.Context, p Profile) (id string, err error)

	// CopyInto copies the contents of srcDir into destPath inside the
	// container. The repo is copied into a container tmpfs; it is never bind
	// mounted from the host.
	CopyInto(ctx context.Context, id, srcDir, destPath string) error

	// Start starts a created container.
	Start(ctx context.Context, id string) error

	// Exec runs cmd inside a running container, streaming output to stdout and
	// stderr. It returns the command's exit code. A non-zero exit code is not
	// reported as an error; only a failure to run the command is.
	Exec(ctx context.Context, id string, cmd []string, stdout, stderr io.Writer) (exitCode int, err error)

	// Remove force-removes the container. It must be safe to call more than
	// once and safe to call with an empty id.
	Remove(ctx context.Context, id string) error
}
