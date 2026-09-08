package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrMonitorUnavailable indicates the egress monitor could not be started or
// could not seal its netns (missing monitor image, no NFLOG support, readiness
// timeout, ...). Execute wraps it around any StartMonitor failure so the CLI can
// distinguish "egress inspection is unavailable on this host" from a real
// sandbox failure and, since inspection is the default, fall back to the fully
// verified --network none mode with a warning instead of failing the run.
var ErrMonitorUnavailable = errors.New("egress monitor unavailable")

// Result summarizes a completed sandbox run.
type Result struct {
	// InstallExitCode is the exit code of the install command run inside the
	// sandbox.
	InstallExitCode int

	// EgressInspected reports whether this run used the packet-level egress
	// monitor. When false, the run used --network none and Egress is nil.
	EgressInspected bool

	// Egress is the deduplicated list of outbound connection attempts the
	// monitor observed and dropped. It is only populated when EgressInspected is
	// true. An empty slice with EgressInspected true means the repo attempted no
	// egress (a clean result), which is distinct from egress not being watched.
	Egress []EgressEvent
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
//	create -> start -> copy repo into tmpfs -> exec install (streamed) -> rm -f
//
// The container is started BEFORE the repo is copied because the copy is done by
// a tar process inside the running container (see DockerRunner.CopyInto);
// Docker refuses `docker cp` into a --read-only container, and the tmpfs mounts
// are only live while the container runs.
//
// SAFETY INVARIANT: cleanup runs on success, on install failure, on panic, and
// on context cancellation (Ctrl-C). The deferred Remove uses a detached context
// with its own timeout so a cancelled ctx does not also cancel the removal. When
// egress inspection is on there are TWO containers (monitor + sandbox); BOTH are
// force-removed, each with its own deferred detached Remove.
func Execute(ctx context.Context, r Runner, opts ExecuteOptions) (result Result, err error) {
	p := opts.Profile.Normalize()

	// Egress inspection (optional): stand up the monitor FIRST so the sandbox can
	// join its network namespace. The monitor is force-removed like the sandbox.
	var (
		inspector   EgressInspector
		monitorName string
	)
	if p.InspectEgress {
		insp, ok := r.(EgressInspector)
		if !ok {
			return Result{}, fmt.Errorf("egress inspection requested but this runner does not support it")
		}
		inspector = insp
		monitorName, err = insp.StartMonitor(ctx, p)
		if err != nil {
			// Wrap ErrMonitorUnavailable so the caller can fall back to
			// --network none (still safe) instead of failing the whole run.
			return Result{}, fmt.Errorf("start egress monitor: %w: %w", ErrMonitorUnavailable, err)
		}
		// Guarantee monitor removal on every path. Deferred LIFO ordering means
		// this runs AFTER the sandbox removal deferred below, so the sandbox
		// (which shares the monitor netns) is gone before the monitor.
		defer removeDetached(r, monitorName, opts.Stderr)
		// The sandbox joins the monitor's netns instead of getting --network none.
		p.NetworkContainer = monitorName
	}

	id, err := r.Create(ctx, p)
	if err != nil {
		return Result{}, fmt.Errorf("create sandbox: %w", err)
	}

	// From here on the container exists; guarantee its removal. Deferred
	// functions run during panic unwinding and after any return, so this covers
	// install failure, panic, and Ctrl-C alike.
	defer removeDetached(r, id, opts.Stderr)

	if err := r.Start(ctx, id); err != nil {
		return Result{}, fmt.Errorf("start sandbox: %w", err)
	}
	if err := r.CopyInto(ctx, id, opts.RepoDir, "/repo"); err != nil {
		return Result{}, fmt.Errorf("copy repo into sandbox: %w", err)
	}

	code, err := r.Exec(ctx, id, p.InstallCmd, opts.Stdout, opts.Stderr)
	if err != nil {
		return Result{}, fmt.Errorf("run install command: %w", err)
	}

	result = Result{InstallExitCode: code}
	if p.InspectEgress {
		result.EgressInspected = true
		// Best-effort: a monitor that fails to report must not fail the run, and
		// the containment guarantee does not depend on the report. Egress stays
		// nil (reported as "unable to read" by the caller) on error.
		events, cErr := inspector.CollectEgress(ctx, monitorName)
		if cErr != nil {
			fmt.Fprintf(opts.Stderr, "meguard: could not read egress monitor: %v\n", cErr)
		} else {
			result.Egress = events
		}
	}
	return result, nil
}

// removeDetached force-removes a container using a detached, time-bounded
// context so a cancelled run (Ctrl-C) still gets cleaned up. It is used for both
// the sandbox and the egress monitor.
func removeDetached(r Runner, id string, stderr io.Writer) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if rmErr := r.Remove(cleanupCtx, id); rmErr != nil {
		fmt.Fprintf(stderr, "meguard: cleanup failed for %s: %v\n", id, rmErr)
	}
}
