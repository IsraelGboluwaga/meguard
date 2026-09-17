//go:build integration

// Package sandbox integration tests exercise a REAL container runtime and
// assert the runtime EFFECTS of the hardening, not just the argv meguard hands
// the runtime. The rest of the suite verifies intent against fakes (fakeRunner,
// fakeDockerBin); these verify enforcement.
//
// They are gated behind the `integration` build tag so the default
// `go test ./...` never needs a runtime or network:
//
//	go test -tags integration ./internal/sandbox/
//
// A runtime is required (docker, or set MEGUARD_IT_RUNTIME=podman/orbstack/...).
// The default image (see DefaultImage) must be pullable or already cached; each
// test skips cleanly when no runtime is reachable, and every container it
// creates is force-removed on every path (invariant 5), including on failure.
package sandbox_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
)

// realRunnerOrSkip returns a DockerRunner backed by an actual runtime, or skips
// the test when none is reachable (so CI without a daemon is green, not red).
func realRunnerOrSkip(t *testing.T) sandbox.DockerRunner {
	t.Helper()
	r := sandbox.DockerRunner{Binary: os.Getenv("MEGUARD_IT_RUNTIME")}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := r.Preflight(ctx); err != nil {
		t.Skipf("no container runtime available, skipping integration test: %v", err)
	}
	return r
}

// startedContainer creates and starts a hardened container from p and registers
// its force-removal for cleanup (invariant 5). It fails the test on any error.
func startedContainer(t *testing.T, r sandbox.DockerRunner, p sandbox.Profile) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	id, err := r.Create(ctx, p.Normalize())
	if err != nil {
		t.Fatalf("Create: %v (is the %q image pullable/cached?)", err, p.Normalize().Image)
	}
	t.Cleanup(func() {
		// Detached context: cleanup must run even if the test's ctx is done.
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		if err := r.Remove(rmCtx, id); err != nil {
			t.Errorf("cleanup Remove(%s): %v", id, err)
		}
	})
	if err := r.Start(ctx, id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return id
}

// TestIntegrationReadOnlyRootfs asserts invariant-adjacent hardening: the
// container rootfs is actually read-only, so a payload cannot persist outside
// the designated tmpfs mounts. Writing to /repo (a tmpfs) must succeed; writing
// to /etc (rootfs) must fail.
func TestIntegrationReadOnlyRootfs(t *testing.T) {
	r := realRunnerOrSkip(t)
	id := startedContainer(t, r, sandbox.Profile{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var out bytes.Buffer
	// /repo is a tmpfs mount: writing there must work.
	if code, err := r.Exec(ctx, id, []string{"sh", "-c", "touch /repo/ok"}, &out, &out); err != nil || code != 0 {
		t.Fatalf("write to /repo tmpfs: exit=%d err=%v out=%s", code, err, out.String())
	}
	// /etc is on the read-only rootfs: writing there must FAIL (non-zero exit).
	out.Reset()
	code, err := r.Exec(ctx, id, []string{"sh", "-c", "touch /etc/meguard-escape"}, &out, &out)
	if err != nil {
		t.Fatalf("Exec (rootfs write attempt) failed to run: %v", err)
	}
	if code == 0 {
		t.Errorf("write to /etc succeeded (exit 0): rootfs is NOT read-only\n  out: %s", out.String())
	}
}

// TestIntegrationEgressDeniedStrict asserts the strongest network mode really
// denies egress: with --network none (the zero-value Profile), an outbound TCP
// connect from inside the container must not succeed. Node is used because it is
// guaranteed present in the default image and needs no extra tooling.
func TestIntegrationEgressDeniedStrict(t *testing.T) {
	r := realRunnerOrSkip(t)
	id := startedContainer(t, r, sandbox.Profile{}) // zero value == --network none

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// exit 0 = connected (FAIL: egress reached the network); exit 3 = connect
	// error (PASS: blocked); exit 4 = timed out (PASS: no route).
	const probe = `const s=require('net').connect(80,'1.1.1.1');` +
		`s.on('connect',()=>process.exit(0));` +
		`s.on('error',()=>process.exit(3));` +
		`setTimeout(()=>process.exit(4),2500);`
	var out bytes.Buffer
	code, err := r.Exec(ctx, id, []string{"node", "-e", probe}, &out, &out)
	if err != nil {
		t.Fatalf("Exec (egress probe) failed to run: %v", err)
	}
	if code == 0 {
		t.Errorf("outbound TCP connect SUCCEEDED: egress is NOT denied under --network none\n  out: %s", out.String())
	}
}

// TestIntegrationRemoveActuallyRemoves asserts invariant 5's mechanism at the
// runtime level: after Remove, the container is gone, so a subsequent Exec
// against the same id fails (it is not merely stopped-but-present).
func TestIntegrationRemoveActuallyRemoves(t *testing.T) {
	r := realRunnerOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id, err := r.Create(ctx, sandbox.Profile{}.Normalize())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.Start(ctx, id); err != nil {
		r.Remove(context.Background(), id)
		t.Fatalf("Start: %v", err)
	}
	if err := r.Remove(ctx, id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// The container must be gone. Exec runs `true`, which returns exactly
	// (0, nil) inside a LIVE container. Against a removed id, `docker exec`
	// exits non-zero ("No such container"), which Exec maps to (nonzero, nil)
	// -- a non-zero exit is not a runner error (see DockerRunner.Exec). So the
	// removed state is anything that is NOT a clean (0, nil).
	var out bytes.Buffer
	code, err := r.Exec(ctx, id, []string{"true"}, &out, &out)
	if code == 0 && err == nil {
		t.Errorf("Exec ran cleanly against a removed container; Remove did not delete it\n  out: %s", out.String())
		r.Remove(context.Background(), id) // best-effort re-cleanup
	}
}
