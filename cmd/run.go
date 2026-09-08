package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/IsraelGboluwaga/meguard/internal/analyze"
	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
	"github.com/spf13/cobra"
)

const sectionRule = "----------------------------------------"

func newRunCmd() *cobra.Command {
	var image string
	var installCmd string
	var runtimeBin string
	var strict bool
	var monitorImage string
	var noScan bool
	var failOnScan bool

	cmd := &cobra.Command{
		Use:   "run <repo-url-or-path>",
		Short: "Clone or copy a repo into a locked-down sandbox and run its install command",
		Long: `run clones a git URL (or copies a local path) into a locked-down container
sandbox and runs an install command inside it. Repo code never runs on the host.

Before anything is executed, run also statically scans the repo's files on the
host (manifest inspection, entropy/long-line detection, and pattern matching
for obfuscation and exfiltration signals; see "meguard scan") and prints a
STATIC SCAN section. This is a container AND a detector in one command: scan
findings are advisory and do not by themselves stop the sandboxed run (the
sandbox's containment is the safety net, not the scan), unless --fail-on-scan
is set.

The container has no network, no host bind mounts, dropped capabilities, a
read-only root, and a scratch HOME that holds no host secrets. The container is
force-removed on exit, panic, or Ctrl-C.

The container daemon is the trust boundary: the hardening flags are only as
strong as the runtime that enforces them. For hostile code, prefer a rootless
runtime via --runtime (for example "podman") so a container escape lands as an
unprivileged user rather than host root.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runSandbox(c.Context(), runOptions{
				source:       args[0],
				image:        image,
				installCmd:   installCmd,
				runtimeBin:   runtimeBin,
				strict:       strict,
				monitorImage: monitorImage,
				noScan:       noScan,
				failOnScan:   failOnScan,
			}, c.OutOrStdout(), c.ErrOrStderr())
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
	// Egress is DENIED in both modes. By default meguard runs in inspected mode
	// (egress dropped AND logged via a monitor sidecar) so you can see what a repo
	// tried to reach. --strict drops to the fully verified --network none (no
	// network stack at all, no logs) for the hardest containment.
	cmd.Flags().BoolVar(&strict, "strict", false, "strictest containment: --network none, no network stack at all and no egress logs (default logs blocked egress; verified on Docker/OrbStack, needs a monitor image with ip/iptables/tcpdump+NFLOG)")
	cmd.Flags().StringVar(&monitorImage, "monitor-image", "", "image for the egress monitor sidecar (default nicolaka/netshoot; must provide ip, iptables, ip6tables, tcpdump+NFLOG)")
	// Scan is advisory by default: it augments the sandboxed run with
	// detection, it does not gate it. --no-scan restores the pre-scan
	// behavior exactly (sandbox only); --fail-on-scan opts INTO gating, for
	// CI callers that want a non-zero exit on a bad finding.
	cmd.Flags().BoolVar(&noScan, "no-scan", false, "skip the static scan entirely (sandbox only, the pre-scan behavior)")
	cmd.Flags().BoolVar(&failOnScan, "fail-on-scan", false, "after the sandboxed run completes, exit non-zero if the static scan reported any High or Critical finding")
	return cmd
}

// runOptions groups the flags for a single run so the signature stays readable
// as options accrue.
type runOptions struct {
	source       string
	image        string
	installCmd   string
	runtimeBin   string
	strict       bool
	monitorImage string
	noScan       bool
	failOnScan   bool
}

func runSandbox(ctx context.Context, o runOptions, stdout, stderr io.Writer) error {
	runner := sandbox.DockerRunner{Binary: o.runtimeBin}

	// Fail fast with actionable guidance if no runtime is reachable, before we
	// clone anything or print a pre-run notice for a run that cannot start.
	if err := runner.Preflight(ctx); err != nil {
		return err
	}

	repoDir, cleanup, err := resolveRepo(ctx, o.source, stderr)
	if err != nil {
		return err
	}
	defer cleanup()

	profile := sandbox.Profile{
		Image: o.image,
		// Egress inspection is the DEFAULT; --strict opts down to --network none.
		// The library zero value (InspectEgress=false) remains the safest one, so
		// this is a CLI-level default, not a change to invariant 3.
		InspectEgress: !o.strict,
		MonitorImage:  o.monitorImage,
	}
	// docker exec runs without a shell, so splitting on whitespace is the right
	// tokenization. Quoted arguments are not supported yet (documented).
	if fields := strings.Fields(o.installCmd); len(fields) > 0 {
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

	printPreRunNotice(stdout, o.source, o.runtimeBin, ecosystem, profile.Normalize())

	// Static scan runs on the host, read-only, before any container work:
	// same safety tier as DetectEcosystem above. Findings are advisory (see
	// the --fail-on-scan flag doc) so the sandboxed run below still proceeds
	// regardless of what scan found; containment, not scan, is the safety
	// net. --no-scan skips this entirely and restores the pre-scan behavior.
	var scanReport analyze.Report
	if !o.noScan {
		var scanErr error
		scanReport, scanErr = analyze.Scan(repoDir)
		if scanErr != nil {
			// A scan failure (e.g. an unreadable repo dir) must not block the
			// sandboxed run: detection is additive, containment is the
			// guarantee. State the failure loudly and continue.
			fmt.Fprintf(stderr, "meguard: static scan failed (%v); continuing with the sandboxed run\n", scanErr)
		} else {
			printScanSection(stdout, stderr, scanReport)
		}
	}

	fmt.Fprintln(stdout, sectionRule)
	fmt.Fprintln(stdout, "SANDBOX OUTPUT")
	fmt.Fprintln(stdout, sectionRule)

	result, err := sandbox.Execute(ctx, runner, sandbox.ExecuteOptions{
		RepoDir: repoDir,
		Profile: profile,
		Stdout:  stdout,
		Stderr:  stderr,
	})
	// Default (inspected) mode is experimental and needs a monitor image + NFLOG.
	// If the monitor cannot start, fall back to the fully verified --network none
	// mode with a loud warning rather than failing the run. This never weakens
	// containment (none is stronger than inspected); it only loses the egress
	// logs, and the fallback is stated, never silent. --strict skips inspection
	// entirely, so there is nothing to fall back from.
	if err != nil && profile.InspectEgress && errors.Is(err, sandbox.ErrMonitorUnavailable) {
		fmt.Fprintf(stderr, "meguard: egress inspection unavailable (%v)\n", err)
		fmt.Fprintln(stderr, "meguard: falling back to --network none (egress still fully denied, but no egress logs). Fix the monitor image/runtime for logs, or pass --strict to require this mode.")
		profile.InspectEgress = false
		result, err = sandbox.Execute(ctx, runner, sandbox.ExecuteOptions{
			RepoDir: repoDir,
			Profile: profile,
			Stdout:  stdout,
			Stderr:  stderr,
		})
	}
	if err != nil {
		return err
	}

	printResult(stdout, result, !o.noScan, scanReport)

	if o.failOnScan {
		if n := highCriticalCount(scanReport); n > 0 {
			return fmt.Errorf("static scan found %d high/critical finding(s) (--fail-on-scan set); see STATIC SCAN section above", n)
		}
	}
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
	if p.InspectEgress {
		fmt.Fprintf(w, "  - network INSPECTED via monitor sidecar (%s): the netns is sealed fail-closed (OUTPUT DROP), every outbound attempt is logged then dropped\n", p.MonitorImageOrDefault())
		fmt.Fprintln(w, "    verified on Docker/OrbStack (Linux); rootless runtimes not yet checked. If the monitor cannot start, meguard falls back to --network none automatically. Pass --strict for the no-stack --network none mode.")
	} else {
		fmt.Fprintln(w, "  - network DENIED (--strict: --network none, no egress, no logs)")
	}
	fmt.Fprintln(w, "  - ephemeral: the container is force-removed on exit, panic, or Ctrl-C")
}

func printResult(w io.Writer, r sandbox.Result, scanned bool, scanReport analyze.Report) {
	fmt.Fprintln(w, sectionRule)
	fmt.Fprintln(w, "RESULT")
	fmt.Fprintln(w, sectionRule)
	fmt.Fprintf(w, "install exit code: %d\n", r.InstallExitCode)
	if r.EgressInspected {
		fmt.Fprintln(w, "0 host secrets exposed (by construction: no host mounts, scratch HOME; egress sealed fail-closed and logged)")
	} else {
		fmt.Fprintln(w, "0 host secrets exposed (by construction: no host mounts, scratch HOME, no network)")
	}
	printEgress(w, r)
	printScanSummaryLine(w, scanned, scanReport)
}

// printScanSummaryLine adds one line to RESULT pointing back at the STATIC
// SCAN section, so a reader scanning only the final summary still sees
// whether anything was flagged.
func printScanSummaryLine(w io.Writer, scanned bool, scanReport analyze.Report) {
	if !scanned {
		fmt.Fprintln(w, "static scan: skipped (--no-scan)")
		return
	}
	if len(scanReport.Findings) == 0 {
		fmt.Fprintln(w, "static scan: clean (0 findings; see STATIC SCAN section above)")
		return
	}
	fmt.Fprintf(w, "static scan: %d finding(s) (%s); see STATIC SCAN section above\n",
		len(scanReport.Findings), formatSeverityCounts(scanReport.Findings))
}

// printEgress renders the blocked-egress report. Nothing leaves the host in any
// case; this only reports what the repo TRIED to do.
func printEgress(w io.Writer, r sandbox.Result) {
	if !r.EgressInspected {
		fmt.Fprintln(w, "egress: not inspected (--network none; egress is fully denied but not logged)")
		return
	}
	if r.EgressReadFailed {
		// Inspected, but the monitor's capture could not be read. Containment
		// still held; only the report is missing. This is NOT the same as a
		// clean run, so it must never be conflated with "0 attempts".
		fmt.Fprintln(w, "egress: inspected, but the monitor output could not be read (see stderr); egress was still blocked")
		return
	}
	if len(r.Egress) == 0 {
		fmt.Fprintln(w, "egress: 0 outbound attempts observed (repo made no network calls during install)")
		return
	}
	fmt.Fprintf(w, "egress: %d outbound attempt(s) BLOCKED (logged and dropped; none reached the network):\n", len(r.Egress))
	for _, e := range r.Egress {
		fmt.Fprintf(w, "  - %s\n", e.String())
	}
}
