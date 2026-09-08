package analyze

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// lifecycleScripts are the package.json script names npm/yarn/pnpm run
// automatically during install, without the user asking for them by name.
// These are exactly the scripts a "run it to see" tool like meguard's sandbox
// is going to trigger.
var lifecycleScripts = []string{"preinstall", "install", "postinstall", "prepare", "preprepare"}

// pythonManifestFiles are Python packaging manifests that can execute
// arbitrary code (a custom setup.py, or a build backend hook) simply by being
// installed. Their presence is inherent ecosystem risk, not evidence of
// anything specific, so it is flagged at Info only.
var pythonManifestFiles = map[string]bool{
	"setup.py":       true,
	"pyproject.toml": true,
	"setup.cfg":      true,
	"Pipfile":        true,
}

type manifestAnalyzer struct{}

func (manifestAnalyzer) Name() string { return "manifest" }

func (manifestAnalyzer) Analyze(files []ScannedFile) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		base := filepath.Base(f.RelPath)
		switch {
		case base == "package.json":
			findings = append(findings, analyzePackageJSON(f)...)
		case pythonManifestFiles[base]:
			findings = append(findings, Finding{
				Analyzer: "manifest",
				Severity: Info,
				File:     f.RelPath,
				Message:  fmt.Sprintf("%s can run arbitrary code at install time (a Python packaging convention); this is inherent to the ecosystem, not evidence on its own", base),
				Count:    1,
			})
		}
	}
	return findings, nil
}

// analyzePackageJSON reads scripts.* and flags lifecycle hooks that run
// automatically on install. A hook is always surfaced (Info at minimum, since
// it runs without being asked for by name); its severity rises if its
// content matches the same risky-pattern set the regex analyzer uses on
// source files, so a hidden curl|sh or Function-eval inside a lifecycle hook
// is caught even though package.json itself is JSON, not source.
func analyzePackageJSON(f ScannedFile) []Finding {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal([]byte(f.Content), &pkg); err != nil {
		// Not valid JSON, or no scripts object: nothing to say. A malformed
		// package.json is not this analyzer's concern.
		return nil
	}

	var findings []Finding
	for _, name := range lifecycleScripts {
		script := pkg.Scripts[name]
		if script == "" {
			continue
		}
		matches := matchPatterns(script)
		if len(matches) == 0 {
			findings = append(findings, Finding{
				Analyzer: "manifest",
				Severity: Info,
				File:     f.RelPath,
				Message:  fmt.Sprintf("package.json defines a %q lifecycle script that runs automatically on install: %s", name, truncate(script, 120)),
				Count:    1,
			})
			continue
		}
		for _, p := range matches {
			findings = append(findings, Finding{
				Analyzer: "manifest",
				Category: p.category,
				Severity: p.severity,
				File:     f.RelPath,
				Message:  fmt.Sprintf("package.json %q lifecycle script matches %s: %s", name, p.description, truncate(script, 160)),
				Snippet:  truncate(script, 160),
				Count:    1,
			})
		}
	}
	return findings
}
