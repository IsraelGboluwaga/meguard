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

	// ExecOutcomes records what each ExecStep did, in order. Empty when no exec
	// steps ran (none configured, or the install failed so the runtime phase was
	// skipped). Egress observed during these steps is folded into Egress above,
	// which is collected once after the LAST step.
	ExecOutcomes []ExecOutcome
}

// ExecStep is one command run inside the sandbox AFTER a successful install, to
// exercise the repo at RUNTIME so a payload that fires at build time or on app
// startup (not at dependency-install time) executes inside the already-sealed
// netns and its egress attempt is observed. Steps run in the order given, in the
// same container as the install, so they see the installed dependency tree.
//
// SAFETY: an ExecStep runs untrusted repo code, exactly like the install command
// already does. It changes nothing about containment: the netns is sealed
// fail-closed before the container exists, there are no host mounts, HOME is a
// scratch tmpfs, and the deferred rm -f still force-removes the container (and
// any long-running process an ExecStep left behind) on every path.
type ExecStep struct {
	// Label is a short human name for the report ("build", "start").
	Label string
	// Cmd is the command to exec inside the container.
	Cmd []string
	// Window, when > 0, bounds this step to a short OBSERVATION WINDOW: the
	// command is started and left to run until it exits on its own OR Window
	// elapses, whichever comes first, and a Window-elapsed kill is treated as
	// SUCCESS (not a failure). Use it for a long-running server that never exits
	// on its own: a startup payload has already fired and been observed by the
	// time the window elapses, and the deferred rm -f kills the lingering process
	// with the container. Zero means run to completion, bounded by InstallTimeout,
	// for a step that exits on its own (a build).
	Window time.Duration
}

// ExecOutcome records what one ExecStep did, for the report. It is never a hard
// error: a runtime phase that cannot complete must not abort the run or discard
// the egress that WAS observed, so every terminal condition is captured here and
// Execute continues to the egress read.
type ExecOutcome struct {
	Label string
	Cmd   []string
	// ExitCode is the command's exit code, or -1 if it did not exit on its own
	// (window-stopped, timed out, cancelled, or failed to launch).
	ExitCode int
	// Observed is true when the step was stopped by its observation Window rather
	// than exiting: the intended outcome for a long-running server, and a SUCCESS
	// condition, not a failure.
	Observed bool
	// TimedOut is true when a non-windowed step (a build) exceeded InstallTimeout.
	TimedOut bool
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

	// ExecSteps are commands run inside the SAME sandbox after a SUCCESSFUL
	// install (install exit code 0), to exercise the repo at runtime. They run in
	// order; a step's non-zero exit or timeout does NOT abort later steps, and
	// egress is collected once after the last one. Empty means install-only (the
	// historical behavior). See ExecStep for the per-step observation-window
	// semantics. When the install exits non-zero these steps are skipped: a failed
	// install usually leaves the app unable to run, so running it would only add
	// noise, not signal.
	ExecSteps []ExecStep
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

	// Runtime phase: after a SUCCESSFUL install, run each configured ExecStep in
	// the SAME sealed container so a payload that fires at build time or on app
	// startup (not at install time) executes inside the netns and its egress is
	// observed. Skipped when the install failed (a broken install usually cannot
	// run the app). Egress is collected ONCE after the last step, below, so it
	// covers install + every exec step together.
	if code == 0 {
		for _, step := range opts.ExecSteps {
			// A parent-ctx cancel (Ctrl-C) between steps: stop launching more and
			// head straight to cleanup.
			if ctx.Err() != nil {
				break
			}
			result.ExecOutcomes = append(result.ExecOutcomes,
				runExecStep(ctx, r, id, step, opts.InstallTimeout, opts.Stdout, opts.Stderr, opts.diag()))
		}
	}

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

// runExecStep runs one ExecStep inside the sandbox and reports what it did. It
// NEVER returns an error: a runtime step that cannot complete (timed out,
// window-stopped, cancelled, or failed to launch) must not abort the run or
// discard the egress already observed, so every terminal condition is folded
// into the returned ExecOutcome and any launch failure is noted on diag.
//
// A windowed step (Window > 0) is bounded by Window; a non-windowed step (a
// build) is bounded by installTimeout, exactly like the install command.
func runExecStep(ctx context.Context, r Runner, id string, step ExecStep, installTimeout time.Duration, stdout, stderr, diag io.Writer) ExecOutcome {
	oc := ExecOutcome{Label: step.Label, Cmd: step.Cmd, ExitCode: -1}

	bound := step.Window
	if bound == 0 {
		bound = installTimeout // a build is bounded like the install; 0 = unbounded
	}
	execCtx := ctx
	if bound > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, bound)
		defer cancel()
	}

	code, err := r.Exec(execCtx, id, step.Cmd, stdout, stderr)
	if err == nil {
		oc.ExitCode = code
		return oc
	}

	// The step did not exit cleanly. A deadline hit with the parent ctx still
	// live is one of our own bounds firing (not a Ctrl-C, which also cancels
	// execCtx); classify it by whether the step was windowed.
	deadline := errors.Is(execCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	switch {
	case step.Window > 0 && deadline:
		// A long-running server we intentionally stopped after its observation
		// window. Expected and successful: startup egress was already captured,
		// and the deferred rm -f kills the process with the container.
		oc.Observed = true
	case deadline:
		// A build (exit-expected step) exceeded InstallTimeout. Not fatal to the
		// run: record it and let egress still be read.
		oc.TimedOut = true
	default:
		// Parent ctx cancelled (Ctrl-C) or a real docker exec launch failure.
		// Non-fatal by design: note it and continue so egress is still collected.
		fmt.Fprintf(diag, "meguard: exec step %q did not complete: %v\n", step.Label, err)
	}
	return oc
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
