package analyze

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// The autorun analyzer flags EDITOR and DEV-ENVIRONMENT configuration files
// that execute a shell command AUTOMATICALLY, before the developer asks for
// anything: a VS Code task pinned to `folderOpen`, a dev-container lifecycle
// command, or a committed git hook. This is a distinct execution vector from a
// package.json lifecycle script (manifest.go) or app source that runs at
// build/start time (the dynamic sandbox): it fires the moment the repo is
// OPENED in an editor or spun up as a dev container, on the HOST, outside any
// sandbox. It is the shape of the "fake interview" VS Code tasks.json
// infostealer -- see docs/decisions.md.
//
// WHY LOCATION, NOT CONTENT, IS THE SIGNAL: the per-line risky-pattern set
// (regex.go) already scans these files' bytes like any other text file, so a
// literal `curl ... | sh` inside a tasks.json is already caught there. What
// regex.go CANNOT see is the pipeless launcher -- `curl -o f && node f`, or a
// bare `node payload.js` that pulls a remote stage 2 -- which is unremarkable
// as a string but sinister BECAUSE OF WHERE IT SITS: an auto-run-on-open
// config has no benign reason to reach the network or spawn a downloaded file.
// So this analyzer keys on the placement (an auto-executing config that runs a
// command at all), independent of whether the command matches a pattern. Its
// findings use the "autorun" category so the correlate pass (analyze.go)
// escalates them further when a regex.go signal lands in the same file.
//
// SAFETY: read-only, like every analyzer here (invariant 1). It only inspects
// ScannedFile bytes; it never parses in a way that could execute, and never
// runs the command it reports.

// folderOpenRe matches a VS Code task pinned to run automatically when the
// folder is opened: "runOn": "folderOpen". Matched on raw content rather than
// via JSON parsing because tasks.json is JSONC (comments, trailing commas)
// which strict JSON parsing rejects, and an attacker can deliberately shape a
// file that VS Code tolerates but encoding/json refuses -- raw matching cannot
// be evaded that way.
var folderOpenRe = regexp.MustCompile(`"runOn"\s*:\s*"folderOpen"`)

// taskCommandRe matches a VS Code task command field, confirming the config
// actually runs something (an empty or comment-only tasks.json is inert).
var taskCommandRe = regexp.MustCompile(`"command"\s*:`)

// devcontainerLifecycleKeys are the dev-container command hooks that run
// automatically when a dev container / Codespace is created, started, or
// attached, without the developer invoking them. postCreateCommand running
// `npm install` is common and legitimate, so the baseline severity is Low; the
// value is surfacing the auto-run surface for review, and correlate escalates
// if a risky pattern co-locates.
var devcontainerLifecycleKeys = []string{
	"onCreateCommand",
	"updateContentCommand",
	"postCreateCommand",
	"postStartCommand",
	"postAttachCommand",
	"initializeCommand",
}

// devcontainerLifecycleRes matches each lifecycle key as a JSON field, built
// once at init rather than per file (the keys are a fixed, small set).
var devcontainerLifecycleRes = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp, len(devcontainerLifecycleKeys))
	for _, key := range devcontainerLifecycleKeys {
		m[key] = regexp.MustCompile(`"` + key + `"\s*:`)
	}
	return m
}()

type autorunAnalyzer struct{}

func (autorunAnalyzer) Name() string { return "autorun" }

func (autorunAnalyzer) Analyze(files []ScannedFile) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		switch {
		case isVSCodeTasksFile(f.RelPath):
			findings = append(findings, analyzeVSCodeTasks(f)...)
		case isDevcontainerFile(f.RelPath):
			findings = append(findings, analyzeDevcontainer(f)...)
		case isCommittedGitHook(f.RelPath):
			findings = append(findings, analyzeGitHook(f)...)
		}
	}
	return findings, nil
}

// isVSCodeTasksFile reports whether relPath is a VS Code tasks.json (which
// lives at .vscode/tasks.json).
func isVSCodeTasksFile(relPath string) bool {
	p := filepath.ToSlash(relPath)
	return strings.HasSuffix(p, ".vscode/tasks.json")
}

// isDevcontainerFile reports whether relPath is a dev-container config
// (.devcontainer/devcontainer.json, a nested .devcontainer/<name>/
// devcontainer.json, or a top-level .devcontainer.json).
func isDevcontainerFile(relPath string) bool {
	p := filepath.ToSlash(relPath)
	if p == ".devcontainer.json" || strings.HasSuffix(p, "/.devcontainer.json") {
		return true
	}
	base := filepath.Base(p)
	if base != "devcontainer.json" {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".devcontainer" {
			return true
		}
	}
	return false
}

// isCommittedGitHook reports whether relPath is a committed git hook: a file
// directly under a .husky/ or .githooks/ directory. Hooks under .git/hooks are
// never committed (and .git is skipped by the walker), so they are not here.
// The husky internal helper directory (.husky/_) is excluded: it holds
// husky's own bootstrap, not a user hook.
func isCommittedGitHook(relPath string) bool {
	p := filepath.ToSlash(relPath)
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if (seg == ".husky" || seg == ".githooks") && i+1 < len(segs) {
			// Directly under the hooks dir (one path element below it),
			// excluding husky's own "_" helper dir.
			if i+2 == len(segs) && segs[i+1] != "_" {
				return true
			}
		}
	}
	return false
}

// analyzeVSCodeTasks flags a tasks.json that runs a command on folderOpen: it
// executes automatically the instant the repo is opened in VS Code, on the
// host, before any inspection. High, because a folderOpen auto-task is
// unusual in a legitimate repo and is the current infostealer vector of
// choice (see docs/decisions.md).
func analyzeVSCodeTasks(f ScannedFile) []Finding {
	if !folderOpenRe.MatchString(f.Content) || !taskCommandRe.MatchString(f.Content) {
		return nil
	}
	return []Finding{{
		Analyzer: "autorun",
		Category: "autorun",
		Severity: High,
		File:     f.RelPath,
		Line:     firstMatchLine(f, folderOpenRe),
		Message:  "VS Code task set to run on folderOpen: this executes a command automatically the moment the repo is opened in VS Code, on the host and outside any sandbox. Do not open this repo in an editor before reviewing it.",
		Count:    1,
	}}
}

// analyzeDevcontainer flags a dev-container config that defines a lifecycle
// command hook, which runs automatically when the container/Codespace is
// created or attached. Low baseline (postCreateCommand running npm install is
// common and legitimate); correlate escalates if a regex.go signal lands in
// the same file.
func analyzeDevcontainer(f ScannedFile) []Finding {
	for _, key := range devcontainerLifecycleKeys {
		if loc := devcontainerLifecycleRes[key].FindStringIndex(f.Content); loc != nil {
			return []Finding{{
				Analyzer: "autorun",
				Category: "autorun",
				Severity: Low,
				File:     f.RelPath,
				Line:     1 + strings.Count(f.Content[:loc[0]], "\n"),
				Message:  fmt.Sprintf("dev-container %q runs a command automatically when the container/Codespace is created or attached; review it before spinning one up", key),
				Count:    1,
			}}
		}
	}
	return nil
}

// analyzeGitHook flags a committed git hook (.husky/ or .githooks/), which git
// runs automatically on the corresponding git operation. Low baseline (husky
// hooks are common and legitimate); correlate escalates if a regex.go signal
// lands in the same file. A hook whose body is only comments/blank is skipped.
func analyzeGitHook(f ScannedFile) []Finding {
	if !hasExecutableBody(f) {
		return nil
	}
	return []Finding{{
		Analyzer: "autorun",
		Category: "autorun",
		Severity: Low,
		File:     f.RelPath,
		Line:     firstExecutableLine(f),
		Message:  fmt.Sprintf("committed git hook (%s): git runs this automatically on the matching git operation; review it before running git in the repo", filepath.Base(f.RelPath)),
		Count:    1,
	}}
}

// hasExecutableBody reports whether a shell script has at least one line that
// is not blank, a comment, or a shebang.
func hasExecutableBody(f ScannedFile) bool {
	return firstExecutableLine(f) > 0
}

// firstExecutableLine returns the 1-based line number of the first
// non-blank, non-comment, non-shebang line, or 0 if there is none.
func firstExecutableLine(f ScannedFile) int {
	for i, line := range f.Lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return i + 1
	}
	return 0
}

// firstMatchLine returns the 1-based line number of re's first match in the
// file, or 0 if it does not match.
func firstMatchLine(f ScannedFile, re *regexp.Regexp) int {
	if loc := re.FindStringIndex(f.Content); loc != nil {
		return 1 + strings.Count(f.Content[:loc[0]], "\n")
	}
	return 0
}
