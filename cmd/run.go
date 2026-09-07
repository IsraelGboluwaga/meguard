package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
	"github.com/spf13/cobra"
)

const sectionRule = "----------------------------------------"

func newRunCmd() *cobra.Command {
	var image string
	var installCmd string
	var runtimeBin string

	cmd := &cobra.Command{
		Use:   "run <repo-url-or-path>",
		Short: "Clone or copy a repo into a locked-down sandbox and run its install command",
		Long: `run clones a git URL (or copies a local path) into a locked-down container
sandbox and runs an install command inside it. Repo code never runs on the host.

The container has no network, no host bind mounts, dropped capabilities, a
read-only root, and a scratch HOME that holds no host secrets. The container is
force-removed on exit, panic, or Ctrl-C.

The container daemon is the trust boundary: the hardening flags are only as
strong as the runtime that enforces them. For hostile code, prefer a rootless
runtime via --runtime (for example "podman") so a container escape lands as an
unprivileged user rather than host root.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runSandbox(c.Context(), args[0], image, installCmd, runtimeBin, c.OutOrStdout(), c.ErrOrStderr())
		},
	}

	// The image and install command are the only two ecosystem-specific values.
	// When left unset they are auto-detected from the repo's manifests (see
	// sandbox.DetectEcosystem); an explicit flag always wins over detection.
	cmd.Flags().StringVar(&image, "image", "", "container image (default: auto-detected from repo, else node:20-slim)")
	cmd.Flags().StringVar(&installCmd, "cmd", "", `install command run inside the sandbox (default: auto-detected from repo, else "npm install")`)
	// The runtime is the trust boundary. Empty means "docker"; any
	// Docker-compatible CLI works (podman, nerdctl, ...). Rootless runtimes
	// shrink the blast radius of a container escape and are preferred for
	// hostile code.
	cmd.Flags().StringVar(&runtimeBin, "runtime", "", `Docker-compatible runtime CLI (default "docker"; e.g. "podman" for rootless)`)
	return cmd
}

func runSandbox(ctx context.Context, source, image, installCmd, runtimeBin string, stdout, stderr io.Writer) error {
	runner := sandbox.DockerRunner{Binary: runtimeBin}

	// Fail fast with actionable guidance if no runtime is reachable, before we
	// clone anything or print a pre-run notice for a run that cannot start.
	if err := runner.Preflight(ctx); err != nil {
		return err
	}

	repoDir, cleanup, err := resolveRepo(ctx, source, stderr)
	if err != nil {
		return err
	}
	defer cleanup()

	profile := sandbox.Profile{Image: image}
	// docker exec runs without a shell, so splitting on whitespace is the right
	// tokenization. Quoted arguments are not supported yet (documented).
	if fields := strings.Fields(installCmd); len(fields) > 0 {
		profile.InstallCmd = fields
	}

	// Auto-detect the ecosystem from the repo's manifests and fill any field the
	// user did not set explicitly. An explicit --image or --cmd always wins;
	// detection only ever supplies the same RELAX values Normalize would, so it
	// cannot weaken the sandbox. Detection reads file existence only and runs no
	// repo code.
	ecosystem := "unknown (using locked-down defaults)"
	if eco, ok := sandbox.DetectEcosystem(repoDir); ok {
		ecosystem = eco.Name
		if profile.Image == "" {
			profile.Image = eco.Image
		}
		if len(profile.InstallCmd) == 0 {
			profile.InstallCmd = eco.InstallCmd
		}
	}

	printPreRunNotice(stdout, source, runtimeBin, ecosystem, profile.Normalize())

	fmt.Fprintln(stdout, sectionRule)
	fmt.Fprintln(stdout, "SANDBOX OUTPUT")
	fmt.Fprintln(stdout, sectionRule)

	result, err := sandbox.Execute(ctx, runner, sandbox.ExecuteOptions{
		RepoDir: repoDir,
		Profile: profile,
		Stdout:  stdout,
		Stderr:  stderr,
	})
	if err != nil {
		return err
	}

	printResult(stdout, result)
	return nil
}

// resolveRepo returns a local directory containing the repo, plus a cleanup
// function. A git URL is cloned to a temp dir that is always removed; a local
// path is used in place with a no-op cleanup.
//
// SAFETY: git clone does NOT run repo install hooks, so it is safe to run on the
// host. All repo EXECUTION happens later, only inside the container.
func resolveRepo(ctx context.Context, source string, stderr io.Writer) (string, func(), error) {
	noop := func() {}

	if isGitURL(source) {
		dir, err := os.MkdirTemp("", "meguard-clone-")
		if err != nil {
			return "", noop, fmt.Errorf("create temp clone dir: %w", err)
		}
		cleanup := func() { _ = os.RemoveAll(dir) }

		// "--" terminates option parsing so a source beginning with "-" can
		// never be smuggled in as a git flag (for example --upload-pack). The
		// isGitURL gate already rejects such strings, but the terminator is
		// unconditional defense in depth on the one command that touches an
		// attacker-controlled string on the host.
		gc := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--", source, dir)
		gc.Stdout = stderr
		gc.Stderr = stderr
		if err := gc.Run(); err != nil {
			cleanup()
			return "", noop, fmt.Errorf("git clone %s: %w", source, err)
		}
		return dir, cleanup, nil
	}

	abs, err := filepath.Abs(source)
	if err != nil {
		return "", noop, fmt.Errorf("resolve repo path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", noop, fmt.Errorf("repo path: %w", err)
	}
	if !info.IsDir() {
		return "", noop, fmt.Errorf("repo path %q is not a directory", abs)
	}
	return abs, noop, nil
}

// isGitURL reports whether source should be treated as a git URL to clone
// rather than a local path to copy.
func isGitURL(source string) bool {
	switch {
	case strings.HasPrefix(source, "http://"),
		strings.HasPrefix(source, "https://"),
		strings.HasPrefix(source, "git://"),
		strings.HasPrefix(source, "ssh://"),
		strings.HasPrefix(source, "git@"):
		return true
	}
	return strings.HasSuffix(source, ".git")
}

func printPreRunNotice(w io.Writer, source, runtimeBin, ecosystem string, p sandbox.Profile) {
	runtimeName := runtimeBin
	if runtimeName == "" {
		runtimeName = "docker"
	}
	fmt.Fprintln(w, "meguard: preparing locked-down sandbox")
	fmt.Fprintf(w, "  source:           %s\n", source)
	fmt.Fprintf(w, "  runtime:          %s (trust boundary)\n", runtimeName)
	fmt.Fprintf(w, "  ecosystem:        %s\n", ecosystem)
	fmt.Fprintf(w, "  image:            %s\n", p.Image)
	fmt.Fprintf(w, "  install command:  %s\n", strings.Join(p.InstallCmd, " "))
	fmt.Fprintln(w, "active protections:")
	fmt.Fprintln(w, "  - repo code NEVER runs on the host (git clone only; all execution in-container)")
	fmt.Fprintln(w, "  - NO host $HOME and NO repo bind mounts (repo is copied into a container tmpfs)")
	fmt.Fprintln(w, "  - network DENIED (--network none, no egress)")
	fmt.Fprintln(w, "  - ephemeral: the container is force-removed on exit, panic, or Ctrl-C")
}

func printResult(w io.Writer, r sandbox.Result) {
	fmt.Fprintln(w, sectionRule)
	fmt.Fprintln(w, "RESULT")
	fmt.Fprintln(w, sectionRule)
	fmt.Fprintf(w, "install exit code: %d\n", r.InstallExitCode)
	fmt.Fprintln(w, "0 host secrets exposed (by construction: no host mounts, scratch HOME, no network)")
	fmt.Fprintln(w, "TODO: surface blocked-egress attempts once an inspecting proxy exists")
}
