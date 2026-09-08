package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/IsraelGboluwaga/meguard/internal/analyze"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan <repo-url-or-path>",
		Short: "Statically scan a repo for signs of hidden malicious code, without running it",
		Long: `scan resolves a git URL (or a local path) the same safe way "run" does (a
plain git clone; cloning does not run install hooks) and then runs meguard's
static analyzers against the repo's files on the host: manifest inspection
(package.json lifecycle scripts), entropy/long-line detection, and pattern
matching for obfuscation, exfiltration channels, and other signals of hidden
malicious code.

scan never touches Docker and never executes repo code; it is entirely
read-only. It is a heuristic detector, not a prover: a clean report means
nothing matched, not "definitely safe". For that guarantee, run the repo
inside the sandbox with "meguard run", which combines this same scan with
containment in one command.

scan exits non-zero if any High or Critical finding is reported, so it can
gate a CI pipeline. Use "meguard run --fail-on-scan" for the same gate while
also containing and observing the repo.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runScan(c.Context(), args[0], c.OutOrStdout(), c.ErrOrStderr())
		},
	}
	return cmd
}

func runScan(ctx context.Context, source string, stdout, stderr io.Writer) error {
	repoDir, cleanup, err := resolveRepo(ctx, source, stderr)
	if err != nil {
		return err
	}
	defer cleanup()

	fmt.Fprintln(stdout, "meguard: static scan (no container; repo code is never executed)")
	fmt.Fprintf(stdout, "  source: %s\n", source)

	report, err := analyze.Scan(repoDir)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	printScanSection(stdout, stderr, report)

	if n := highCriticalCount(report); n > 0 {
		return fmt.Errorf("static scan found %d high/critical finding(s); see STATIC SCAN section above", n)
	}
	return nil
}

// printScanSection renders a Report the same way in both "meguard scan" and
// the "STATIC SCAN" section of "meguard run". Per-file skip reasons are
// summarized on stdout and detailed on stderr so the main report stays
// scannable.
func printScanSection(stdout, stderr io.Writer, report analyze.Report) {
	fmt.Fprintln(stdout, sectionRule)
	fmt.Fprintln(stdout, "STATIC SCAN")
	fmt.Fprintln(stdout, sectionRule)
	fmt.Fprintf(stdout, "files scanned: %d\n", report.FilesScanned)
	if report.ASTEnabled {
		fmt.Fprintln(stdout, "AST analysis: enabled")
	} else {
		// Absence of AST is stated, not silent: a clean scan on this build is
		// never presented as "AST found nothing".
		fmt.Fprintf(stdout, "AST analysis: disabled (%s)\n", report.ASTDisabledReason)
	}
	if len(report.Errors) > 0 {
		fmt.Fprintf(stdout, "scan warnings: %d file(s)/analyzer(s) skipped (see stderr for detail)\n", len(report.Errors))
		for _, e := range report.Errors {
			fmt.Fprintf(stderr, "meguard: scan warning: %s\n", e)
		}
	}

	if len(report.Findings) == 0 {
		fmt.Fprintln(stdout, "findings: none (advisory: a heuristic scan finding nothing is not a guarantee the repo is safe)")
		return
	}

	fmt.Fprintf(stdout, "findings: %d (%s)\n", len(report.Findings), formatSeverityCounts(report.Findings))
	for _, f := range report.Findings {
		fmt.Fprintf(stdout, "  - %s\n", f.String())
		if f.Snippet != "" {
			fmt.Fprintf(stdout, "      %s\n", f.Snippet)
		}
	}
}

// severityOrder lists severities from most to least important, for stable,
// human-prioritized output.
var severityOrder = []analyze.Severity{analyze.Critical, analyze.High, analyze.Medium, analyze.Low, analyze.Info}

func formatSeverityCounts(findings []analyze.Finding) string {
	counts := map[analyze.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range severityOrder {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}

// highCriticalCount reports how many findings are High or Critical severity.
// This is what --fail-on-scan and "meguard scan"'s exit code gate on:
// findings below that bar are advisory only.
func highCriticalCount(report analyze.Report) int {
	n := 0
	for _, f := range report.Findings {
		if f.Severity >= analyze.High {
			n++
		}
	}
	return n
}
