package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
	var verbose bool
	var noPrefetch bool
	var installTimeout time.Duration
	var noExec bool
	var execCmd string
	var execWindow time.Duration

	cmd := &cobra.Command{
		Use:   "run <repo-url-or-path>",
		Short: "Clone or copy a repo into a locked-down sandbox, install, then run it",
		Long: `run clones a git URL (or copies a local path) into a locked-down container
sandbox, installs it, then RUNS it inside the same sandbox. Repo code never runs
on the host.

After a successful install, run also EXECUTES the repo at runtime (auto-detected
build then start/serve; see --exec-cmd) inside the sealed container, so a payload
that only fires when the app builds or starts (not at dependency-install time)
executes where the egress monitor can observe it. A long-running server is given
a short observation window (--exec-window) and then stopped. Pass --no-exec to
install only. This runtime phase is dynamic and partial: it observes what fires
during the window, and complements (does not replace) the static scan.

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
				verbose:      verbose,
				noPrefetch:   noPrefetch,
				timeout:      installTimeout,
				noExec:       noExec,
				execCmd:      execCmd,
				execWindow:   execWindow,
			}, c.OutOrStdout(), c.ErrOrStderr())
		},
	}

	// The image and install command are the only two ecosystem-specific values.
	// When left unset they are auto-detected from the repo's manifests (see
	// sandbox.DetectEcosystem); an explicit flag always wins over detection.
	cmd.Flags().StringVar(&image, "image", "", "container image (default: auto-detected from repo, else node:22-slim)")
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
	// Default output is a compact status checklist plus only the High/Critical
	// findings (see printCompactReport): enough to see at a glance whether the
	// repo is worth trusting, without the full protections prose, every
	// finding, and the raw install log. --verbose restores that full detail.
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print full detail: protections rationale, every scan finding, and the raw install log")
	// Two-phase install (node only): by default meguard prefetches the dependency
	// tree with `npm install --ignore-scripts` inside a hardened, networked,
	// no-host-mount container (runs NO repo code), then installs OFFLINE inside the
	// sealed sandbox so dependency postinstall payloads actually run and their
	// blocked egress is observed. --no-prefetch keeps the single-phase behavior
	// (sandbox has no network, so a networked install fails fast; only the repo's
	// own root scripts run).
	cmd.Flags().BoolVar(&noPrefetch, "no-prefetch", false, "skip the containerized dependency prefetch; run single-phase (node install then has no network, so dependency scripts never run)")
	// The install command runs real, possibly hostile lifecycle scripts in the
	// box; bound it so a hung or spinning script cannot stall meguard. Applies to
	// both the prefetch and the in-sandbox install. 0 disables the timeout.
	cmd.Flags().DurationVar(&installTimeout, "timeout", 2*time.Minute, "max duration for the dependency prefetch and for the in-sandbox install command (0 disables)")
	// After a successful install, meguard executes the repo at runtime inside the
	// SAME sealed sandbox so a build-time or startup payload runs where the egress
	// monitor sees it. --no-exec keeps the install-only behavior. --exec-cmd
	// overrides the auto-detected build-then-serve plan with a single command.
	cmd.Flags().BoolVar(&noExec, "no-exec", false, "skip the runtime execution phase; install only (do not build or start the repo)")
	cmd.Flags().StringVar(&execCmd, "exec-cmd", "", "run this exact command inside the sandbox after install instead of the auto-detected build/start plan")
	// A dev server or long-running app never exits on its own; run it under a
	// short observation window (its startup payload has fired by then) and stop
	// it. A build step, which exits, is bounded by --timeout instead.
	cmd.Flags().DurationVar(&execWindow, "exec-window", 3*time.Second, "observation window for a long-running run/serve step before it is stopped")
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
	verbose      bool
	noPrefetch   bool
	timeout      time.Duration
	noExec       bool
	execCmd      string
	execWindow   time.Duration
}

func runSandbox(ctx context.Context, o runOptions, stdout, stderr io.Writer) error {
	runner := sandbox.DockerRunner{Binary: o.runtimeBin}

	// In compact mode the slow stages (static scan, and the in-container
	// install) print nothing until they finish, which looks frozen. A spinner
	// on stderr fills that gap; it is inert on a non-terminal stderr and unused
	// in verbose mode, which streams its own live output instead.
	var sp *spinner
	if !o.verbose {
		sp = newSpinner(stderr)
	}

	// Fail fast with actionable guidance if no runtime is reachable, before we
	// clone anything or print a pre-run notice for a run that cannot start.
	if err := runner.Preflight(ctx); err != nil {
		return err
	}

	repoDir, owned, cleanup, err := resolveRepo(ctx, o.source, stderr)
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
	userSetCmd := false
	if fields := strings.Fields(o.installCmd); len(fields) > 0 {
		profile.InstallCmd = fields
		userSetCmd = true
	}

	// Auto-detect the ecosystem from the repo's manifests and fill any field the
	// user did not set explicitly. An explicit --image or --cmd always wins;
	// detection only ever supplies the same RELAX values Normalize would, so it
	// cannot weaken the sandbox. Detection reads file existence only and runs no
	// repo code.
	ecosystem := "unknown (using locked-down defaults)"
	eco, ecoOK := sandbox.DetectEcosystem(repoDir)
	if ecoOK {
		ecosystem = eco.Name
		if profile.Image == "" {
			profile.Image = eco.Image
		}
	}

	// Decide the two-phase (offline) install. Prefetch is attempted only when the
	// ecosystem defines a containerized, no-code-execution fetch (node today), the
	// user did not override --cmd, and --no-prefetch was not passed. When it will
	// run, the sandbox install is the OFFLINE form so a full dependency tree is
	// built with the network sealed and every lifecycle script runs in the box;
	// otherwise the ecosystem's single-phase (fail-fast) install is used. A user
	// --cmd always wins over both.
	willPrefetch := ecoOK && !o.noPrefetch && !userSetCmd && len(eco.PrefetchCmd) > 0
	if !userSetCmd && len(profile.InstallCmd) == 0 && ecoOK {
		if willPrefetch {
			profile.InstallCmd = eco.OfflineInstallCmd
		} else {
			profile.InstallCmd = eco.InstallCmd
		}
	}

	if o.verbose {
		printPreRunNotice(stdout, o.source, o.runtimeBin, ecosystem, profile.Normalize())
	}

	// Two-phase leg 1: containerized prefetch (node). Stage an unowned (user's own)
	// repo into a copy first so meguard never writes the cache into the user's
	// tree. Prefetch runs no repo code (invariant 1); on any failure it falls back
	// to the single-phase install, still fully contained.
	prefetch := prefetchOutcome{Detail: "not applicable"}
	if willPrefetch {
		staged, stageCleanup, stageErr := stageForMutation(repoDir, owned)
		if stageErr != nil {
			fmt.Fprintf(stderr, "meguard: %v; falling back to single-phase install\n", stageErr)
			profile.InstallCmd = eco.InstallCmd
			prefetch = prefetchOutcome{Attempted: true, OK: false, Detail: "staging failed; single-phase"}
		} else {
			defer stageCleanup()
			repoDir = staged
			// The prefetch's npm log is streamed live in --verbose mode (under a
			// header, like the sandbox install), and in compact mode captured into
			// a buffer that is discarded on success and flushed only if prefetch
			// fails, since that is the one case where the log is the thing to debug.
			// A clean prefetch's npm output (EBADENGINE warnings, deprecations, the
			// package count) is noise. Cleanup diagnostics always go to the real
			// stderr regardless, never into this buffer (see runPrefetch's diag).
			var prefetchLog bytes.Buffer
			prefetchOut := io.Writer(&prefetchLog)
			if o.verbose {
				fmt.Fprintln(stdout, sectionRule)
				fmt.Fprintln(stdout, "PREFETCH OUTPUT")
				fmt.Fprintln(stdout, sectionRule)
				prefetchOut = stdout
			}
			sp.start("prefetching dependencies in a networked, no-host-mount container (no scripts run)")
			prefetch = runPrefetch(ctx, runner, eco, repoDir, o.timeout, prefetchOut, stderr)
			sp.stop()
			if !prefetch.OK {
				profile.InstallCmd = eco.InstallCmd
				// Prefetch failed: its npm log is now the diagnostic the user needs,
				// so flush the captured buffer (compact mode only; verbose already
				// streamed it live).
				if !o.verbose {
					io.Copy(stderr, &prefetchLog)
				}
			}
		}
	}

	// Static scan runs on the host, read-only, before any container work:
	// same safety tier as DetectEcosystem above. Findings are advisory (see
	// the --fail-on-scan flag doc) so the sandboxed run below still proceeds
	// regardless of what scan found; containment, not scan, is the safety
	// net. --no-scan skips this entirely and restores the pre-scan behavior.
	var scanReport analyze.Report
	if !o.noScan {
		var scanErr error
		sp.start("scanning repo for hidden code")
		scanReport, scanErr = analyze.Scan(repoDir)
		sp.stop()
		if scanErr != nil {
			// A scan failure (e.g. an unreadable repo dir) must not block the
			// sandboxed run: detection is additive, containment is the
			// guarantee. State the failure loudly and continue.
			fmt.Fprintf(stderr, "meguard: static scan failed (%v); continuing with the sandboxed run\n", scanErr)
		} else if o.verbose {
			printScanSection(stdout, stderr, scanReport)
		}
	}

	// Runtime execution phase (default on): after a SUCCESSFUL install, meguard
	// runs the repo inside the SAME sealed sandbox so a payload that fires at
	// build time or on startup (not at dependency-install time) executes where
	// the egress monitor observes it. --no-exec skips it entirely; --exec-cmd
	// overrides the auto-detected build-then-serve plan with one explicit command.
	// Detection reads only file existence and package.json data (invariant 1;
	// same tier as DetectEcosystem) and only ever supplies commands to run in the
	// box, never a security control (invariant 3). repoDir here is the FINAL dir
	// (a staged copy when prefetch ran), which carries the same manifests.
	var execSteps []sandbox.ExecStep
	if !o.noExec {
		if fields := strings.Fields(o.execCmd); len(fields) > 0 {
			execSteps = []sandbox.ExecStep{{Label: strings.Join(fields, " "), Cmd: fields, Window: o.execWindow}}
		} else if ecoOK {
			execSteps = sandbox.DetectExecPlan(repoDir, eco, o.execWindow)
		}
	}

	// The raw install log is streamed live in --verbose mode (as before). In
	// compact mode it is captured instead of streamed, and only shown if the
	// install actually failed (exit != 0) or the run itself errors, since
	// that is the one case where the log is the thing you need to debug; a
	// clean install's log is noise (see the npm "Exit handler never called!"
	// warning in the report that prompted this).
	var installLog bytes.Buffer
	instStdout, instStderr := stdout, stderr
	if o.verbose {
		fmt.Fprintln(stdout, sectionRule)
		fmt.Fprintln(stdout, "SANDBOX OUTPUT")
		fmt.Fprintln(stdout, sectionRule)
	} else {
		instStdout, instStderr = &installLog, &installLog
	}

	runMsg := fmt.Sprintf("running %s in locked-down sandbox (%s)", strings.Join(profile.InstallCmd, " "), profile.Image)
	if len(execSteps) > 0 {
		runMsg = fmt.Sprintf("install then run (%s) in locked-down sandbox (%s)", execStepsSummary(execSteps), profile.Image)
	}
	sp.start(runMsg)
	result, err := sandbox.Execute(ctx, runner, sandbox.ExecuteOptions{
		RepoDir: repoDir,
		Profile: profile,
		Stdout:  instStdout,
		Stderr:  instStderr,
		// Diag is ALWAYS the real stderr, regardless of --verbose: meguard's
		// own operational diagnostics (cleanup failures, egress-monitor-read
		// failures) must never be silently lost inside installLog just
		// because the install itself succeeded. Only the install command's
		// own stdio (Stdout/Stderr above) is ever buffered away.
		Diag:           stderr,
		InstallTimeout: o.timeout,
		ExecSteps:      execSteps,
	})
	// Default (inspected) mode is experimental and needs a monitor image + NFLOG.
	// If the monitor cannot start, fall back to the fully verified --network none
	// mode with a loud warning rather than failing the run. This never weakens
	// containment (none is stronger than inspected); it only loses the egress
	// logs, and the fallback is stated, never silent. --strict skips inspection
	// entirely, so there is nothing to fall back from.
	if err != nil && profile.InspectEgress && errors.Is(err, sandbox.ErrMonitorUnavailable) {
		sp.stop()
		fmt.Fprintf(stderr, "meguard: egress inspection unavailable (%v)\n", err)
		fmt.Fprintln(stderr, "meguard: falling back to --network none (egress still fully denied, but no egress logs). Fix the monitor image/runtime for logs, or pass --strict to require this mode.")
		profile.InspectEgress = false
		sp.start(runMsg)
		result, err = sandbox.Execute(ctx, runner, sandbox.ExecuteOptions{
			RepoDir:        repoDir,
			Profile:        profile,
			Stdout:         instStdout,
			Stderr:         instStderr,
			Diag:           stderr,
			InstallTimeout: o.timeout,
			ExecSteps:      execSteps,
		})
	}
	sp.stop()
	if err != nil {
		if !o.verbose && installLog.Len() > 0 {
			fmt.Fprintln(stderr, "meguard: install log:")
			stderr.Write(installLog.Bytes())
		}
		return err
	}

	if o.verbose {
		printResult(stdout, result, execSteps, !o.noScan, scanReport)
	} else {
		// When the containerized prefetch already failed, its npm log was flushed
		// above as the root-cause diagnostic. The sealed single-phase fallback then
		// runs with no network and an unpopulated cache, so it fails with a
		// foregone getaddrinfo/EAI_AGAIN error whose actual cause is the prefetch
		// failure already shown. Dumping that second log stacks redundant noise on
		// top of the real cause, so suppress it in that case; the compact report's
		// prefetch and install lines still record that both failed.
		prefetchFailed := prefetch.Attempted && !prefetch.OK
		if result.InstallExitCode != 0 && installLog.Len() > 0 && !prefetchFailed {
			fmt.Fprintln(stdout, sectionRule)
			fmt.Fprintln(stdout, "INSTALL LOG (install exited non-zero)")
			fmt.Fprintln(stdout, sectionRule)
			stdout.Write(installLog.Bytes())
		}
		printCompactReport(stdout, profile, result, prefetch, execSteps, !o.noScan, scanReport)
	}

	if o.failOnScan {
		if n := highCriticalCount(scanReport); n > 0 {
			return fmt.Errorf("static scan found %d high/critical finding(s) (--fail-on-scan set); see the findings above", n)
		}
	}
	return nil
}

// resolveRepo returns a local directory containing the repo, plus a cleanup
// function. A git URL is cloned to a temp dir that is always removed; a local
// path is used in place with a no-op cleanup.
//
// The returned owned flag reports whether repoDir is a directory meguard created
// and may freely mutate (a clone temp: owned=true) versus the user's own working
// tree used in place (owned=false). The two-phase prefetch writes into the repo
// dir, so an unowned dir must be staged into a copy first (see stageForMutation).
//
// SAFETY: git clone does NOT run repo install hooks, so it is safe to run on the
// host. All repo EXECUTION happens later, only inside the container.
func resolveRepo(ctx context.Context, source string, stderr io.Writer) (repoDir string, owned bool, cleanup func(), err error) {
	noop := func() {}

	if isGitURL(source) {
		dir, err := os.MkdirTemp("", "meguard-clone-")
		if err != nil {
			return "", false, noop, fmt.Errorf("create temp clone dir: %w", err)
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
			return "", false, noop, fmt.Errorf("git clone %s: %w", source, err)
		}
		return dir, true, cleanup, nil
	}

	abs, err := filepath.Abs(source)
	if err != nil {
		return "", false, noop, fmt.Errorf("resolve repo path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", false, noop, fmt.Errorf("repo path: %w", err)
	}
	if !info.IsDir() {
		return "", false, noop, fmt.Errorf("repo path %q is not a directory", abs)
	}
	return abs, false, noop, nil
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

func printResult(w io.Writer, r sandbox.Result, execSteps []sandbox.ExecStep, scanned bool, scanReport analyze.Report) {
	fmt.Fprintln(w, sectionRule)
	fmt.Fprintln(w, "RESULT")
	fmt.Fprintln(w, sectionRule)
	fmt.Fprintf(w, "install exit code: %d\n", r.InstallExitCode)
	printExecResult(w, execSteps, r)
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

// printCompactReport is the default (non--verbose) "meguard run" output: a
// one-line-per-stage status checklist, the top scan findings (see
// printTopFindings in scan.go), and a single free-text RESULT line. It
// intentionally omits the protections rationale and the raw install log
// (printed separately, only on install failure) that --verbose keeps.
func printCompactReport(w io.Writer, p sandbox.Profile, r sandbox.Result, prefetch prefetchOutcome, execSteps []sandbox.ExecStep, scanned bool, report analyze.Report) {
	netDesc := "network denied (--strict, no logs)"
	if p.InspectEgress {
		netDesc = "network inspected (fail-closed)"
	}
	fmt.Fprintf(w, "%s sandbox    %s, %s, ephemeral\n", glyphOK, p.Image, netDesc)

	printCompactPrefetchLine(w, prefetch)

	installGlyph := glyphOK
	if r.InstallExitCode != 0 {
		installGlyph = glyphBad
	}
	fmt.Fprintf(w, "%s install    %s (exit %d)\n", installGlyph, strings.Join(p.InstallCmd, " "), r.InstallExitCode)

	printCompactExecLine(w, execSteps, r)

	highCrit := 0
	if scanned {
		highCrit = highCriticalCount(report)
		scanGlyph := glyphOK
		if highCrit > 0 {
			scanGlyph = glyphWarn
		}
		fmt.Fprintf(w, "%s scan       %d finding(s) (%s) across %d files\n",
			scanGlyph, len(report.Findings), formatSeverityCounts(report.Findings), report.FilesScanned)
	} else {
		fmt.Fprintln(w, "- scan       skipped (--no-scan)")
	}

	printCompactEgressLine(w, r)

	fmt.Fprintf(w, "%s secrets    0 exposed (by construction: no host mounts, scratch HOME)\n", glyphOK)

	if scanned {
		printTopFindings(w, report.Findings, "meguard run -v")
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "RESULT: %s\n", summarizeCompactResult(r, scanned, highCrit))
}

// summarizeCompactResult is the single closing sentence of the compact
// report: the same facts as the verbose RESULT section, condensed to what a
// reader deciding whether to trust the repo actually needs.
func summarizeCompactResult(r sandbox.Result, scanned bool, highCrit int) string {
	var parts []string
	if r.InstallExitCode == 0 {
		parts = append(parts, "clean install")
	} else {
		parts = append(parts, fmt.Sprintf("install failed (exit %d)", r.InstallExitCode))
	}
	parts = append(parts, "0 secrets exposed")
	if r.EgressInspected && !r.EgressReadFailed && len(r.Egress) > 0 {
		parts = append(parts, fmt.Sprintf("%d egress attempt(s) blocked, none reached the network", len(r.Egress)))
	} else {
		parts = append(parts, "no egress reached the network")
	}
	summary := strings.Join(parts, ", ") + "."
	if !scanned {
		return summary
	}
	if highCrit > 0 {
		return summary + fmt.Sprintf(" Review the %d high/critical finding(s) above before trusting this repo.", highCrit)
	}
	return summary + " No high/critical scan findings."
}

// printCompactPrefetchLine is the one-line prefetch summary for the status
// checklist. It states plainly whether dependencies were fetched offline (so
// dependency lifecycle scripts run in the box) or the run is single-phase (only
// the repo's own root scripts run, because the sandbox has no network).
func printCompactPrefetchLine(w io.Writer, prefetch prefetchOutcome) {
	switch {
	case prefetch.Attempted && prefetch.OK:
		fmt.Fprintf(w, "%s prefetch   dependencies fetched in a no-host-mount container (no scripts run); deps install in-box\n", glyphOK)
	case prefetch.Attempted && !prefetch.OK:
		fmt.Fprintf(w, "%s prefetch   %s\n", glyphWarn, prefetch.Detail)
	default:
		fmt.Fprintln(w, "- prefetch   single-phase (sandbox has no network; dependency scripts do not run)")
	}
}

// printCompactEgressLine is the one-line egress summary for the status
// checklist; printEgress (below) renders the full per-attempt list used by
// --verbose.
func printCompactEgressLine(w io.Writer, r sandbox.Result) {
	switch {
	case !r.EgressInspected:
		fmt.Fprintf(w, "%s egress     denied (--network none, no logs)\n", glyphOK)
	case r.EgressReadFailed:
		fmt.Fprintf(w, "%s egress     inspected, but monitor output could not be read (containment still held; see stderr)\n", glyphWarn)
	case len(r.Egress) == 0:
		fmt.Fprintf(w, "%s egress     0 attempts observed, 0 reached the network\n", glyphOK)
	default:
		fmt.Fprintf(w, "%s egress     %d blocked (%s), 0 reached the network\n", glyphOK, len(r.Egress), egressDestSummary(r.Egress))
	}
}

// printCompactExecLine is the one-line runtime-execution summary for the status
// checklist. It states whether the repo was actually run after install and what
// each step did (a build that exited, a server observed then stopped), or why
// the phase was skipped.
func printCompactExecLine(w io.Writer, steps []sandbox.ExecStep, r sandbox.Result) {
	switch {
	case len(steps) == 0:
		fmt.Fprintln(w, "- exec       skipped (--no-exec, or no runnable entry detected)")
	case r.InstallExitCode != 0:
		fmt.Fprintf(w, "- exec       skipped (install exited %d; app not run)\n", r.InstallExitCode)
	case len(r.ExecOutcomes) == 0:
		fmt.Fprintln(w, "- exec       not run")
	default:
		fmt.Fprintf(w, "%s exec       %s\n", glyphOK, execOutcomeSummary(r.ExecOutcomes))
	}
}

// printExecResult renders the runtime-execution phase in the verbose RESULT
// section, one line per step, mirroring printCompactExecLine's states.
func printExecResult(w io.Writer, steps []sandbox.ExecStep, r sandbox.Result) {
	switch {
	case len(steps) == 0:
		fmt.Fprintln(w, "runtime execution: skipped (--no-exec, or no runnable entry detected)")
		return
	case r.InstallExitCode != 0:
		fmt.Fprintf(w, "runtime execution: skipped (install exited %d; app not run)\n", r.InstallExitCode)
		return
	case len(r.ExecOutcomes) == 0:
		fmt.Fprintln(w, "runtime execution: not run")
		return
	}
	fmt.Fprintln(w, "runtime execution (in the same sealed sandbox):")
	for _, o := range r.ExecOutcomes {
		fmt.Fprintf(w, "  - %s: %s [%s]\n", o.Label, execOutcomeState(o), strings.Join(o.Cmd, " "))
	}
}

// execStepsSummary is a short comma-joined list of step labels for the spinner
// message (for example "build, start").
func execStepsSummary(steps []sandbox.ExecStep) string {
	labels := make([]string, 0, len(steps))
	for _, s := range steps {
		labels = append(labels, s.Label)
	}
	return strings.Join(labels, ", ")
}

// execOutcomeSummary renders the runtime-execution outcomes as one line, e.g.
// "ran build (exit 0), start (observed 3s, stopped)".
func execOutcomeSummary(outs []sandbox.ExecOutcome) string {
	parts := make([]string, 0, len(outs))
	for _, o := range outs {
		parts = append(parts, fmt.Sprintf("%s (%s)", o.Label, execOutcomeState(o)))
	}
	return "ran " + strings.Join(parts, ", ")
}

// execOutcomeState is the human phrase for a single step's terminal state. A
// window-observed server and a clean exit are both successes; a timeout or a
// step that never launched are noted plainly.
func execOutcomeState(o sandbox.ExecOutcome) string {
	switch {
	case o.Observed:
		return "observed then stopped"
	case o.TimedOut:
		return "timed out"
	case o.ExitCode < 0:
		return "did not run"
	default:
		return fmt.Sprintf("exit %d", o.ExitCode)
	}
}

// egressDestSummary renders up to 3 distinct destinations from a blocked
// egress list, plus a rollup count, so the checklist line stays one line
// even when a repo made many attempts.
func egressDestSummary(events []sandbox.EgressEvent) string {
	const maxShown = 3
	seen := map[string]bool{}
	var dests []string
	for _, e := range events {
		if seen[e.Dest] {
			continue
		}
		seen[e.Dest] = true
		dests = append(dests, e.Dest)
	}
	if len(dests) > maxShown {
		shown := dests[:maxShown]
		return fmt.Sprintf("%s, +%d more", strings.Join(shown, ", "), len(dests)-maxShown)
	}
	return strings.Join(dests, ", ")
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
