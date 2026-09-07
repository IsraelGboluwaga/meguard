package sandbox_test

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
)

// fakeRunner is a Runner test double that records the lifecycle calls it
// receives and returns configurable results, so Execute's orchestration and its
// cleanup guarantee can be tested without a container daemon.
type fakeRunner struct {
	createID  string
	createErr error
	copyErr   error
	startErr  error
	execCode  int
	execErr   error
	execPanic bool

	calls       []string
	removeCalls int
	gotProfile  sandbox.Profile
	gotExecCmd  []string
}

func (f *fakeRunner) Create(_ context.Context, p sandbox.Profile) (string, error) {
	f.calls = append(f.calls, "create")
	f.gotProfile = p
	if f.createErr != nil {
		return "", f.createErr
	}
	id := f.createID
	if id == "" {
		id = "fake-id"
	}
	return id, nil
}

func (f *fakeRunner) CopyInto(_ context.Context, _, _, _ string) error {
	f.calls = append(f.calls, "copy")
	return f.copyErr
}

func (f *fakeRunner) Start(_ context.Context, _ string) error {
	f.calls = append(f.calls, "start")
	return f.startErr
}

func (f *fakeRunner) Exec(_ context.Context, _ string, cmd []string, _, _ io.Writer) (int, error) {
	f.calls = append(f.calls, "exec")
	f.gotExecCmd = cmd
	if f.execPanic {
		panic("boom in exec")
	}
	return f.execCode, f.execErr
}

func (f *fakeRunner) Remove(_ context.Context, _ string) error {
	f.calls = append(f.calls, "remove")
	f.removeCalls++
	return nil
}

func opts() sandbox.ExecuteOptions {
	return sandbox.ExecuteOptions{
		RepoDir: "/unused/in/fake",
		Stdout:  io.Discard,
		Stderr:  io.Discard,
	}
}

func TestExecuteHappyPath(t *testing.T) {
	f := &fakeRunner{execCode: 7}
	res, err := sandbox.Execute(context.Background(), f, opts())
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if res.InstallExitCode != 7 {
		t.Errorf("InstallExitCode = %d, want 7", res.InstallExitCode)
	}
	wantOrder := []string{"create", "start", "copy", "exec", "remove"}
	if !reflect.DeepEqual(f.calls, wantOrder) {
		t.Errorf("call order = %v, want %v", f.calls, wantOrder)
	}
	if f.removeCalls != 1 {
		t.Errorf("Remove called %d times, want 1", f.removeCalls)
	}
}

// A non-zero install exit code is a repo outcome, not a runner error.
func TestExecuteNonZeroExitIsNotError(t *testing.T) {
	f := &fakeRunner{execCode: 1}
	res, err := sandbox.Execute(context.Background(), f, opts())
	if err != nil {
		t.Fatalf("Execute returned error for non-zero exit: %v", err)
	}
	if res.InstallExitCode != 1 {
		t.Errorf("InstallExitCode = %d, want 1", res.InstallExitCode)
	}
	if f.removeCalls != 1 {
		t.Errorf("Remove called %d times, want 1", f.removeCalls)
	}
}

// If Create fails there is no container yet, so Remove must NOT be called.
func TestExecuteCreateErrorSkipsRemove(t *testing.T) {
	f := &fakeRunner{createErr: errors.New("boom")}
	_, err := sandbox.Execute(context.Background(), f, opts())
	if err == nil {
		t.Fatal("expected error when Create fails")
	}
	if !strings.Contains(err.Error(), "create sandbox") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "create sandbox")
	}
	if f.removeCalls != 0 {
		t.Errorf("Remove called %d times after Create failure, want 0", f.removeCalls)
	}
	if !reflect.DeepEqual(f.calls, []string{"create"}) {
		t.Errorf("calls = %v, want [create]", f.calls)
	}
}

// INVARIANT 5: once a container exists, Remove MUST run on every failure path.
func TestExecuteAlwaysRemovesAfterCreate(t *testing.T) {
	tests := []struct {
		name    string
		runner  *fakeRunner
		wantMsg string
	}{
		{"copy fails", &fakeRunner{copyErr: errors.New("x")}, "copy repo into sandbox"},
		{"start fails", &fakeRunner{startErr: errors.New("x")}, "start sandbox"},
		{"exec fails", &fakeRunner{execErr: errors.New("x")}, "run install command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sandbox.Execute(context.Background(), tt.runner, opts())
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantMsg)
			}
			if tt.runner.removeCalls != 1 {
				t.Errorf("Remove called %d times, want 1 (invariant 5)", tt.runner.removeCalls)
			}
		})
	}
}

// INVARIANT 5: cleanup must run even when the install step panics.
func TestExecuteRemovesContainerOnPanic(t *testing.T) {
	f := &fakeRunner{execPanic: true}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = sandbox.Execute(context.Background(), f, opts())
	}()
	if recovered == nil {
		t.Fatal("expected the panic to propagate through Execute")
	}
	if f.removeCalls != 1 {
		t.Errorf("Remove called %d times on panic, want 1 (invariant 5)", f.removeCalls)
	}
}

// A zero-value Profile must be normalized to the locked-down defaults before the
// container is created and the install command is run.
func TestExecuteNormalizesProfile(t *testing.T) {
	f := &fakeRunner{}
	if _, err := sandbox.Execute(context.Background(), f, opts()); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if f.gotProfile.Image != sandbox.DefaultImage {
		t.Errorf("Create got image %q, want default %q", f.gotProfile.Image, sandbox.DefaultImage)
	}
	if !reflect.DeepEqual(f.gotExecCmd, sandbox.DefaultInstallCmd()) {
		t.Errorf("Exec got cmd %v, want default %v", f.gotExecCmd, sandbox.DefaultInstallCmd())
	}
}
