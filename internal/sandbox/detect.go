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
	//
	// This is the SINGLE-PHASE (online-attempt) form and the fallback whenever
	// PrefetchCmd is empty or prefetch fails. Under the sandbox it has no network,
	// so it fails fast (the ecosystem flags below force zero retries); the value
	// is that the repo's ROOT lifecycle scripts still fire and any egress attempt
	// is logged and dropped.
	InstallCmd []string

	// PrefetchCmd, when non-empty, downloads the dependency tree into a cache
	// WITHOUT executing any repo or dependency lifecycle code (for node:
	// `npm install --ignore-scripts`). It is the first leg of the two-phase
	// install and runs inside a hardened, networked, no-host-mount PREFETCH
	// CONTAINER (sandbox.RunPrefetch), never on the host, so an untrusted local
	// dependency spec cannot reach host files. The populated cache is copied back
	// out so the second leg installs fully OFFLINE inside the sealed sandbox,
	// where dependency postinstall payloads fire and their (blocked, logged)
	// egress is observed.
	//
	// SAFETY: PrefetchCmd must run NO repo lifecycle script (that is what keeps
	// the networked prefetch container safe). Only ecosystems whose fetch has a
	// provably no-code-execution mode get one; see the node vs python split in
	// detectNode/detectPython. Empty means the ecosystem stays single-phase and
	// only InstallCmd is used.
	//
	// The literal token CacheDirPlaceholder in PrefetchCmd is substituted for the
	// in-container cache path (ContainerCacheDir) by the caller before execution.
	PrefetchCmd []string

	// OfflineInstallCmd is the sandbox install command used when PrefetchCmd ran
	// successfully: it installs strictly from the prefetched cache with the
	// network sealed, so a complete dependency tree (root AND transitive) is
	// built and every lifecycle script executes inside the box. It is only
	// consulted after a successful prefetch; otherwise InstallCmd is used.
	OfflineInstallCmd []string
}

// Prefetch cache location. CacheDirName is a directory created under the staged
// repo on the host by the prefetch step; because it lives inside the repo dir it
// travels into the sandbox with the normal tar copy and lands at ContainerCacheDir
// (/repo/<name>), where the offline install reads it. It is deliberately dot-
// prefixed and repo-relative so it needs no extra mount and is cleaned up with the
// staged repo. CacheDirPlaceholder is substituted for the absolute HOST cache path
// inside PrefetchCmd before the prefetch runs.
const (
	CacheDirName        = ".meguard-cache"
	ContainerCacheDir   = "/repo/" + CacheDirName
	CacheDirPlaceholder = "__MEGUARD_CACHE_DIR__"
)

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
				Name:  "node",
				Image: DefaultImage,
				// Single-phase fallback: attempted online, but --fetch-retries=0
				// makes the (always denied) network fail immediately instead of
				// backing off for minutes. Root lifecycle scripts still fire.
				InstallCmd: []string{"npm", "install", "--no-audit", "--no-fund", "--fetch-retries=0"},
				// Two-phase leg 1 (PREFETCH CONTAINER): --ignore-scripts downloads
				// and links the full dependency tree but runs NO lifecycle script of
				// the root or any dependency, so no untrusted code runs. This command
				// executes inside a hardened, networked, no-host-mount container (see
				// sandbox.RunPrefetch / prefetchCreateArgs), NOT on the host, so a
				// malicious local dependency spec (file:/overrides/...) resolves
				// against the container's own filesystem and can never read a host
				// file. --cache points at the in-container cache path (substituted
				// from CacheDirPlaceholder), which is copied back out for leg 2.
				// --registry pins the public registry for determinism (defense in
				// depth against a repo .npmrc that redirects it; the fetched tarballs
				// are inert here and only run later in the sealed sandbox regardless).
				PrefetchCmd: []string{
					"npm", "install",
					"--ignore-scripts", "--no-audit", "--no-fund",
					"--registry=https://registry.npmjs.org/",
					"--cache", CacheDirPlaceholder,
				},
				// Two-phase leg 2 (SEALED SANDBOX): install strictly OFFLINE from the
				// prefetched cache. The network is sealed, so --offline both
				// guarantees no egress path is needed and fails fast if anything
				// is missing. Every lifecycle script (root AND transitive deps)
				// runs here, in the box, where its egress is logged and dropped.
				OfflineInstallCmd: []string{"npm", "install", "--offline", "--no-audit", "--no-fund", "--cache", ContainerCacheDir},
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
		return pythonEcosystem([]string{"pip", "install", "--user", "--retries", "0", "--timeout", "5", "-r", "requirements.txt"}), true
	}
	for _, marker := range []string{
		"pyproject.toml",
		"setup.py",
		"setup.cfg",
		"Pipfile",
	} {
		if fileExists(filepath.Join(root, marker)) {
			return pythonEcosystem([]string{"pip", "install", "--user", "--retries", "0", "--timeout", "5", "."}), true
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
// fail trying to write the read-only system site-packages. The callers add
// --retries 0 --timeout 5 so the (always denied) network fails fast rather than
// retrying for minutes.
//
// Python is deliberately SINGLE-PHASE: it has no PrefetchCmd. Unlike npm's
// --ignore-scripts, there is no host-side pip fetch that provably runs no repo
// code: `pip download`/`pip wheel` execute a source distribution's setup.py to
// resolve metadata, which would run untrusted code on the host and break
// invariant 1. A contained Python prefetch is future work (see docs/decisions.md);
// until then Python gets fast-fail + a bounded timeout but not offline completion.
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
