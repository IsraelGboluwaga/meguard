package sandbox

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Result summarizes a completed sandbox run.
type Result struct {
	// InstallExitCode is the exit code of the install command run inside the
	// sandbox.
	InstallExitCode int
}

// ExecuteOptions configures a single Execute run.
type ExecuteOptions struct {
	// RepoDir is a local directory whose CONTENTS are copied into the sandbox
	// tmpfs. It is never bind mounted.
	RepoDir string
	// Profile selects the image, install command, and resource ceilings. Its
	// zero value is fully locked down.
	Profile Profile
	// Stdout and Stderr receive the streamed sandbox output.
	Stdout io.Writer
	Stderr io.Writer
}

// cleanupTimeout bounds the detached removal so cleanup cannot hang forever.
const cleanupTimeout = 30 * time.Second

// Execute runs the full sandbox lifecycle and ALWAYS force-removes the
// container:
//
//	create -> copy repo into tmpfs -> start -> exec install (streamed) -> rm -f
//
// SAFETY INVARIANT: cleanup runs on success, on install failure, on panic, and
// on context cancellation (Ctrl-C). The deferred Remove uses a detached context
// with its own timeout so a cancelled ctx does not also cancel the removal.
func Execute(ctx context.Context, r Runner, opts ExecuteOptions) (result Result, err error) {
	p := opts.Profile.Normalize()

	id, err := r.Create(ctx, p)
	if err != nil {
		return Result{}, fmt.Errorf("create sandbox: %w", err)
	}

	// From here on the container exists; guarantee its removal. Deferred
	// functions run during panic unwinding and after any return, so this covers
	// install failure, panic, and Ctrl-C alike.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if rmErr := r.Remove(cleanupCtx, id); rmErr != nil {
			fmt.Fprintf(opts.Stderr, "meguard: cleanup failed for %s: %v\n", id, rmErr)
		}
	}()

	if err := r.CopyInto(ctx, id, opts.RepoDir, "/repo"); err != nil {
		return Result{}, fmt.Errorf("copy repo into sandbox: %w", err)
	}
	if err := r.Start(ctx, id); err != nil {
		return Result{}, fmt.Errorf("start sandbox: %w", err)
	}

	code, err := r.Exec(ctx, id, p.InstallCmd, opts.Stdout, opts.Stderr)
	if err != nil {
		return Result{}, fmt.Errorf("run install command: %w", err)
	}
	return Result{InstallExitCode: code}, nil
}
