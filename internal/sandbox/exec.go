package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// DetectExecPlan inspects the repo to decide which commands to run INSIDE the
// sandbox after a successful install, so the app is exercised at runtime and a
// payload that fires at build time or on startup (not at install time) executes
// inside the sealed netns where its egress is observed. It returns an ordered
// list of ExecStep, or nil when no runnable entry point is recognized.
//
// The plan is build-then-serve: a build step (if the ecosystem has one) runs to
// completion, then a serve step runs under a short OBSERVATION WINDOW because a
// dev server or long-running app never exits on its own. serveWindow is the
// window applied to the serve step; the build step is always Window 0 (bounded
// by the install timeout instead, since it exits).
//
// SAFETY: like DetectEcosystem, this is READ-ONLY host-side inspection. It reads
// file existence and parses package.json as data (encoding/json); it never
// executes repo code, so invariant 1 holds. Choosing which command to run is not
// running it: the commands only ever run later, inside the sealed container.
// Detection also only supplies commands to run in the box; it can never weaken a
// security control (invariant 3).
func DetectExecPlan(repoDir string, eco Ecosystem, serveWindow time.Duration) []ExecStep {
	switch eco.Name {
	case "node":
		return nodeExecPlan(repoDir, serveWindow)
	case "python":
		return pythonExecPlan(repoDir, serveWindow)
	default:
		return nil
	}
}

// packageJSON is the subset of package.json fields the exec planner reads. All
// other fields are ignored; unknown fields do not fail the parse.
type packageJSON struct {
	Scripts map[string]string `json:"scripts"`
	Main    string            `json:"main"`
}

// nodeExecPlan builds the runtime plan for a Node repo from package.json. A
// `build` script (if present) runs first to completion; then the first available
// long-running entry is served under the observation window, preferring an
// explicit `start`, then `dev`, then `serve` script, then the package `main`,
// then a top-level index.js. Returns nil when none of those exist.
//
// npm start is invoked as `npm start` (npm special-cases it); every other script
// as `npm run <name>`.
func nodeExecPlan(repoDir string, serveWindow time.Duration) []ExecStep {
	pkg, ok := readPackageJSON(repoDir)
	if !ok {
		return nil
	}

	var steps []ExecStep
	if _, has := pkg.Scripts["build"]; has {
		steps = append(steps, ExecStep{Label: "build", Cmd: []string{"npm", "run", "build"}})
	}

	var serve []string
	var serveLabel string
	switch {
	case scriptPresent(pkg.Scripts, "start"):
		serve, serveLabel = []string{"npm", "start"}, "start"
	case scriptPresent(pkg.Scripts, "dev"):
		serve, serveLabel = []string{"npm", "run", "dev"}, "dev"
	case scriptPresent(pkg.Scripts, "serve"):
		serve, serveLabel = []string{"npm", "run", "serve"}, "serve"
	case pkg.Main != "" && fileExists(filepath.Join(repoDir, pkg.Main)):
		serve, serveLabel = []string{"node", pkg.Main}, "node "+pkg.Main
	case fileExists(filepath.Join(repoDir, "index.js")):
		serve, serveLabel = []string{"node", "index.js"}, "node index.js"
	}
	if serve != nil {
		steps = append(steps, ExecStep{Label: serveLabel, Cmd: serve, Window: serveWindow})
	}
	return steps
}

// pythonExecPlan builds the runtime plan for a Python repo: run the recognized
// entry script under the observation window. It prefers main.py, then app.py,
// then any single top-level .py (the loose fake-interview script shape). Returns
// nil when no top-level entry is found. There is no build step for Python.
//
// It never guesses a framework runner (for example Django manage.py runserver),
// which would need arguments and a bound port; a project that must be launched a
// specific way is run explicitly with --exec-cmd.
func pythonExecPlan(repoDir string, serveWindow time.Duration) []ExecStep {
	for _, entry := range []string{"main.py", "app.py"} {
		if fileExists(filepath.Join(repoDir, entry)) {
			return []ExecStep{{Label: "python " + entry, Cmd: []string{"python", entry}, Window: serveWindow}}
		}
	}
	if entry, ok := singleTopLevelPyFile(repoDir); ok {
		return []ExecStep{{Label: "python " + entry, Cmd: []string{"python", entry}, Window: serveWindow}}
	}
	return nil
}

// readPackageJSON reads and parses the repo's package.json as DATA. A missing or
// unparseable file yields ok=false (no plan), never an error that stops the run:
// the runtime phase is additive, and a repo with a malformed manifest simply
// gets no auto-detected exec plan.
func readPackageJSON(repoDir string) (packageJSON, bool) {
	b, err := os.ReadFile(filepath.Join(repoDir, "package.json"))
	if err != nil {
		return packageJSON{}, false
	}
	var pkg packageJSON
	if err := json.Unmarshal(b, &pkg); err != nil {
		return packageJSON{}, false
	}
	return pkg, true
}

// scriptPresent reports whether a non-empty script by that name exists.
func scriptPresent(scripts map[string]string, name string) bool {
	v, ok := scripts[name]
	return ok && v != ""
}

// singleTopLevelPyFile returns the name of the sole top-level .py file when the
// repo root contains exactly one, so a loose single-script repo has an
// unambiguous entry point. With zero or more than one it returns ok=false rather
// than guess which script is the entry.
func singleTopLevelPyFile(repoDir string) (string, bool) {
	entries, err := os.ReadDir(repoDir)
	if err != nil {
		return "", false
	}
	var found string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".py" {
			continue
		}
		if found != "" {
			return "", false // more than one; ambiguous
		}
		found = e.Name()
	}
	return found, found != ""
}
