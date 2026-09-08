package sandbox

import (
	"os"
	"path/filepath"
)

// Ecosystem is a repository ecosystem recognized from its manifest files, plus
// the sandbox defaults that fit it: which image to run and which install
// command to execute inside the container.
//
// SAFETY: detection only ever supplies the two RELAX values on a Profile (Image
// and InstallCmd; see profile.go). It never touches a security control, so a
// detected ecosystem cannot weaken the sandbox. Detection also only READS the
// existence of top-level files and never executes anything, so invariant 1 (no
// host execution of repo code) holds: choosing an image is not running code.
type Ecosystem struct {
	// Name is a short human label for the pre-run notice, for example "node" or
	// "python".
	Name string
	// Image is the container image that fits this ecosystem.
	Image string
	// InstallCmd is the install command run inside the sandbox. It is chosen to
	// work under the locked-down box (non-root uid 1000, read-only root): for
	// example pip is given --user so its writes land on the /home/sandbox tmpfs
	// rather than the read-only system site-packages.
	InstallCmd []string
}

// detectors is the ordered list of ecosystem detectors. The first one to match
// the repo root wins, so order encodes precedence. Node precedes Python: a
// polyglot repo carrying both a package.json and Python manifests is treated as
// Node, the dominant ecosystem among the untrusted "take-home" repos meguard
// targets. To add an ecosystem, add a detector to this slice; nothing else in
// the pipeline changes.
var detectors = []func(repoRoot string) (Ecosystem, bool){
	detectNode,
	detectPython,
}

// DetectEcosystem inspects the repo root (top-level manifest files only, NOT
// recursively) and returns the ecosystem it recognizes plus true, or a zero
// Ecosystem and false when nothing matches. Callers that get false fall back to
// the locked-down Profile defaults via Normalize.
func DetectEcosystem(repoDir string) (Ecosystem, bool) {
	for _, detect := range detectors {
		if eco, ok := detect(repoDir); ok {
			return eco, true
		}
	}
	return Ecosystem{}, false
}

// detectNode recognizes a Node/npm repo from any of the standard manifest or
// lockfiles. It reuses the package defaults so node detection can never drift
// from DefaultImage / DefaultInstallCmd. yarn.lock or pnpm-lock.yaml still map
// to `npm install` because node:20-slim ships only npm; running the install at
// all is what exercises the repo's lifecycle scripts, which is the point.
func detectNode(root string) (Ecosystem, bool) {
	for _, marker := range []string{
		"package.json",
		"package-lock.json",
		"npm-shrinkwrap.json",
		"yarn.lock",
		"pnpm-lock.yaml",
	} {
		if fileExists(filepath.Join(root, marker)) {
			return Ecosystem{
				Name:       "node",
				Image:      DefaultImage,
				InstallCmd: DefaultInstallCmd(),
			}, true
		}
	}
	return Ecosystem{}, false
}

// detectPython recognizes a Python repo. requirements.txt is the most direct
// install target, so it is preferred; otherwise a project manifest
// (pyproject.toml / setup.py / setup.cfg / Pipfile) means an installable
// package, so the project itself is installed, which runs its build and setup
// hooks - exactly the untrusted step meguard wants observed inside the box.
//
// As a last resort, a repo with a top-level *.py file but no manifest at all
// (a loose script, for example a fake-interview repo that is a single .py with
// no requirements.txt) is still recognized as Python so the sandbox lands in
// the right ecosystem image instead of falling back to node and running
// `npm install` against a missing package.json. There is nothing to install in
// that case, so the install command is a NO-OP (`python --version`): it never
// executes repo code, so invariant 1 holds and an untrusted script is not run
// automatically. The user runs the actual script explicitly with --cmd.
func detectPython(root string) (Ecosystem, bool) {
	if fileExists(filepath.Join(root, "requirements.txt")) {
		return pythonEcosystem([]string{"pip", "install", "--user", "-r", "requirements.txt"}), true
	}
	for _, marker := range []string{
		"pyproject.toml",
		"setup.py",
		"setup.cfg",
		"Pipfile",
	} {
		if fileExists(filepath.Join(root, marker)) {
			return pythonEcosystem([]string{"pip", "install", "--user", "."}), true
		}
	}
	if hasTopLevelPyFile(root) {
		return pythonEcosystem([]string{"python", "--version"}), true
	}
	return Ecosystem{}, false
}

// hasTopLevelPyFile reports whether root directly contains a regular file with
// a .py extension. It reads the top-level directory only (no recursion) and
// never opens or executes any file, so it keeps detection read-only and
// invariant 1 intact: choosing a Python image is not running code.
func hasTopLevelPyFile(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".py" {
			return true
		}
	}
	return false
}

// pythonEcosystem builds a Python Ecosystem with the given install command.
// --user (set by callers) sends installs to $HOME/.local on the /home/sandbox
// tmpfs, which is writable under the read-only root; a plain `pip install` would
// fail trying to write the read-only system site-packages.
func pythonEcosystem(cmd []string) Ecosystem {
	return Ecosystem{
		Name:       "python",
		Image:      "python:3.12-slim",
		InstallCmd: cmd,
	}
}

// fileExists reports whether path exists and is a regular file (not a
// directory). Detection keys off manifest files, so a directory named like a
// manifest must not count.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
