package cmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/IsraelGboluwaga/meguard/internal/analyze"
	"github.com/spf13/cobra"
)

// Status glyphs used by the compact (non--verbose) checklist output of both
// "meguard run" and "meguard scan".
const (
	glyphOK   = "✓"
	glyphWarn = "!"
	glyphBad  = "✗"
)

func newScanCmd() *cobra.Command {
	var verbose bool
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
			return runScan(c.Context(), args[0], verbose, c.OutOrStdout(), c.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print every finding in full, not just High/Critical")
	return cmd
}

func runScan(ctx context.Context, source string, verbose bool, stdout, stderr io.Writer) error {
	repoDir, cleanup, err := resolveRepo(ctx, source, stderr)
	if err != nil {
		return err
	}
	defer cleanup()

	if verbose {
		fmt.Fprintln(stdout, "meguard: static scan (no container; repo code is never executed)")
		fmt.Fprintf(stdout, "  source: %s\n", source)
	} else {
		fmt.Fprintf(stdout, "meguard scan %s (no container; read-only)\n\n", source)
	}

	report, err := analyze.Scan(repoDir)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if verbose {
		printScanSection(stdout, stderr, report)
	} else {
		printCompactScanSection(stdout, stderr, report)
	}

	if n := highCriticalCount(report); n > 0 {
		return fmt.Errorf("static scan found %d high/critical finding(s); see the findings above", n)
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

// printCompactScanSection is the default (non--verbose) scan report: a one-
// line summary plus printTopFindings, instead of every finding in full. Used
// by both "meguard scan" and the compact "meguard run" checklist.
func printCompactScanSection(stdout, stderr io.Writer, report analyze.Report) {
	if len(report.Errors) > 0 {
		for _, e := range report.Errors {
			fmt.Fprintf(stderr, "meguard: scan warning: %s\n", e)
		}
	}
	scanGlyph := glyphOK
	if highCriticalCount(report) > 0 {
		scanGlyph = glyphWarn
	}
	fmt.Fprintf(stdout, "%s scan       %d finding(s) (%s) across %d files\n",
		scanGlyph, len(report.Findings), scanSummaryOrClean(report), report.FilesScanned)
	printTopFindings(stdout, report.Findings, "meguard scan -v")
}

func scanSummaryOrClean(report analyze.Report) string {
	if len(report.Findings) == 0 {
		return "clean"
	}
	return formatSeverityCounts(report.Findings)
}

// maxTopFindings caps how many High/Critical findings the compact view lists
// individually before rolling the rest into one summary line.
const maxTopFindings = 8

// printTopFindings renders every High/Critical finding (up to maxTopFindings)
// as one line each, then rolls everything else into a single "N more"
// summary line via restHint. If there are no High/Critical findings at all,
// it shows the single highest-severity finding as a representative sample so
// the block is never empty while findings exist.
func printTopFindings(w io.Writer, findings []analyze.Finding, verboseCmd string) {
	if len(findings) == 0 {
		return
	}

	var top, rest []analyze.Finding
	for _, f := range findings {
		if f.Severity >= analyze.High && len(top) < maxTopFindings {
			top = append(top, f)
		} else {
			rest = append(rest, f)
		}
	}
	if len(top) == 0 {
		// findings is sorted highest-severity-first (see sortFindings).
		top = findings[:1]
		rest = findings[1:]
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Top findings:")
	for _, f := range top {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "  %-8s %-40s %s\n", strings.ToUpper(f.Severity.String()), loc, f.Message)
	}
	if len(rest) > 0 {
		fmt.Fprintf(w, "  ... %d more (%s). see `%s`\n", len(rest), restHint(rest), verboseCmd)
	}
}

// restHint summarizes the findings rolled up past maxTopFindings: which
// analyzer(s) they came from, and, when one directory accounts for most of
// them, a pointer at it -- the shape of noisy-but-benign findings, e.g. a UI
// library's own long class-name strings all living under one components dir.
func restHint(rest []analyze.Finding) string {
	analyzerCounts := map[string]int{}
	dirCounts := map[string]int{}
	for _, f := range rest {
		analyzerCounts[f.Analyzer]++
		dirCounts[filepath.Dir(f.File)]++
	}

	var byAnalyzer []string
	for _, a := range sortedKeysByCountDesc(analyzerCounts) {
		byAnalyzer = append(byAnalyzer, fmt.Sprintf("%d %s", analyzerCounts[a], a))
	}
	hint := strings.Join(byAnalyzer, ", ")

	if dir, n := topKey(dirCounts); dir != "" && dir != "." && n*2 > len(rest) {
		hint += fmt.Sprintf(", mostly %s/*", dir)
	}
	return hint
}

// sortedKeysByCountDesc returns m's keys ordered by count descending, then
// alphabetically, so restHint's output is deterministic.
func sortedKeysByCountDesc(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// topKey returns the key with the highest count in m (alphabetical tie-break
// for determinism), and its count. Returns "", 0 for an empty map.
func topKey(m map[string]int) (string, int) {
	keys := sortedKeysByCountDesc(m)
	if len(keys) == 0 {
		return "", 0
	}
	return keys[0], m[keys[0]]
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
