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
	// true. Empty with EgressInspected true and EgressReadFailed false means the
	// repo attempted no egress (a clean result).
	Egress []EgressEvent

	// EgressReadFailed is true when egress was inspected but the monitor's
	// capture could not be read (so Egress is unknown, NOT known-empty). This is
	// distinct from a clean run: containment still held either way. It is the
	// only signal for "could not read", so zero attempts is never misreported as
	// a read failure.
	EgressReadFailed bool
}

// ExecuteOptions configures a single Execute run.
type ExecuteOptions struct {
	// RepoDir is a local directory whose CONTENTS are copied into the sandbox
	// tmpfs. It is never bind mounted.
	RepoDir string
	// Profile selects the image, install command, and resource ceilings. Its
	// zero value is fully locked down.
	Profile Profile
	// Stdout and Stderr receive the streamed sandbox output (the install
	// command's own stdio).
	Stdout io.Writer
	Stderr io.Writer
	// Diag receives meguard's OWN operational diagnostics (cleanup failures,
	// egress-monitor-read failures), separate from the install command's own
	// stdio above. Optional: when nil, these fall back to Stderr, matching
	// the historical behavior of sharing one writer for both. A caller that
	// captures Stdout/Stderr into a buffer it may discard (e.g. to keep a
	// clean install's log out of a compact report) should set Diag to a
	// writer it does NOT discard, so a cleanup or monitor-read failure is
	// never silently lost regardless of whether the install itself
	// succeeded.
	Diag io.Writer

	// InstallTimeout bounds ONLY the install command's execution (create, start,
	// and copy are fast and stay on the parent ctx). Zero means no timeout. When
	// it elapses the install exec is cancelled, the run returns ErrInstallTimeout,
	// and cleanup still force-removes every container via the deferred detached
	// Remove. This is the ceiling that keeps a hostile or hung lifecycle script
	// (a real one now runs in-box under the two-phase offline install) from
	// stalling meguard indefinitely.
	InstallTimeout time.Duration
}

// ErrInstallTimeout is returned by Execute when the install command exceeds
// ExecuteOptions.InstallTimeout. Containment is unaffected: cleanup still runs.
var ErrInstallTimeout = errors.New("install command timed out")

// diag returns where to write meguard's own operational diagnostics: Diag if
// set, else Stderr (preserving the old behavior for any caller that has not
// set Diag).
func (o ExecuteOptions) diag() io.Writer {
	if o.Diag != nil {
		return o.Diag
	}
	return o.Stderr
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
		defer removeDetached(r, monitorName, opts.diag())
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
	defer removeDetached(r, id, opts.diag())

	if err := r.Start(ctx, id); err != nil {
		return Result{}, fmt.Errorf("start sandbox: %w", err)
	}
	if err := r.CopyInto(ctx, id, opts.RepoDir, "/repo"); err != nil {
		return Result{}, fmt.Errorf("copy repo into sandbox: %w", err)
	}

	// Bound ONLY the install exec with InstallTimeout (if set); create/start/copy
	// stay on the parent ctx. A cancelled execCtx kills the docker exec but not
	// the deferred detached Remove, so cleanup still runs.
	execCtx := ctx
	if opts.InstallTimeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, opts.InstallTimeout)
		defer cancel()
	}
	code, err := r.Exec(execCtx, id, p.InstallCmd, opts.Stdout, opts.Stderr)
	if err != nil {
		// Distinguish "we cancelled the install for exceeding InstallTimeout"
		// from a genuine runner failure: only the former is a timeout, and only
		// when the PARENT ctx is still live (a real Ctrl-C also cancels execCtx).
		if opts.InstallTimeout > 0 && errors.Is(execCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return Result{}, fmt.Errorf("%w after %s", ErrInstallTimeout, opts.InstallTimeout)
		}
		return Result{}, fmt.Errorf("run install command: %w", err)
	}

	result = Result{InstallExitCode: code}
	if p.InspectEgress {
		result.EgressInspected = true
		// Give the monitor's tcpdump a moment to flush its last captured lines to
		// the container log before we read them. Without this, a single fast
		// packet (e.g. one DNS query from an install that exits immediately) can
		// race the read and be missed even though it was captured and dropped.
		settle(ctx, monitorFlushDelay)
		// Best-effort: a monitor that fails to report must not fail the run, and
		// the containment guarantee does not depend on the report. On a read
		// error EgressReadFailed is set so the caller says "could not read"
		// rather than misreporting zero attempts.
		events, cErr := inspector.CollectEgress(ctx, monitorName)
		if cErr != nil {
			fmt.Fprintf(opts.diag(), "meguard: could not read egress monitor: %v\n", cErr)
			result.EgressReadFailed = true
		} else {
			result.Egress = events
		}
	}
	return result, nil
}

// monitorFlushDelay is how long Execute waits after the install command exits
// for the monitor's line-buffered tcpdump to flush its last captured lines to
// the container log before CollectEgress reads them.
const monitorFlushDelay = 1200 * time.Millisecond

// settle sleeps for d, but returns early if ctx is cancelled (Ctrl-C).
func settle(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
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
