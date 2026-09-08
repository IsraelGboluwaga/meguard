package analyze

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxScanFileSize bounds how large a single file scan will read into memory.
// Files over this size are skipped (not read, not flagged); this keeps scan
// fast and bounded on repos that carry large generated or media assets.
const maxScanFileSize = 5 << 20 // 5 MiB

// skipDirNames are directories walkFiles never descends into: version
// control metadata, third-party dependency trees, and inert tool caches.
//
// The dependency trees (node_modules, vendor, venv/.venv/env, .tox, .eggs)
// hold installed third-party package code, which CAN carry a malicious
// payload -- but the same is true of node_modules, which has always been
// skipped here, so this is a consistent, deliberate tradeoff, not a hole.
// It rests on the tool's design: containment (the sandboxed run), not the
// advisory scan, is the safety net for whatever a dependency ships, and in
// the normal clone-then-scan flow these trees are usually gitignored and
// created at install time inside the container, not committed. The caches
// (__pycache__, .mypy_cache, .pytest_cache) are inert generated data
// (JSON/text), not an execution vector; skipping them is pure noise and
// time reduction. Python .egg-info metadata dirs are a glob, not a fixed
// name, so they are matched separately (see isGeneratedMetadataDir).
//
// dist/ and build/ are DELIBERATELY NOT here: an attacker could plant a
// payload disguised as a build artifact, so those directories are still
// walked and still get the specific signature checks (packer, Function-eval,
// obfuscator fingerprint, webhook URLs, ...). Only the generic long-line/
// entropy check excludes them (see isMinifiedOrVendorPath in this file and
// its use in entropy.go), because minification alone is normal there and not
// evidence of anything by itself.
var skipDirNames = map[string]bool{
	".git":          true,
	"node_modules":  true,
	"vendor":        true,
	".next":         true,
	"__pycache__":   true,
	"venv":          true,
	".venv":         true,
	"env":           true,
	".tox":          true,
	".eggs":         true,
	".mypy_cache":   true,
	".pytest_cache": true,
	// meguard's own two-phase prefetch cache (sandbox.CacheDirName). When `run`
	// prefetches, it lives inside the staged repo dir the scan walks; it holds
	// npm's compressed package blobs, which are inert here and only add noise and
	// entropy false positives. The literal is duplicated rather than imported to
	// keep internal/analyze free of any dependency on internal/sandbox.
	".meguard-cache": true,
}

// isGeneratedMetadataDir reports whether name is a Python packaging metadata
// directory (foo.egg-info / foo.dist-info). These are generated, inert text
// metadata (PKG-INFO, entry_points.txt, RECORD, ...), not hand-edited source,
// so they only add noise. Matched by suffix because the name is a glob keyed
// on the package name, which skipDirNames (an exact-match map) cannot express.
func isGeneratedMetadataDir(name string) bool {
	return strings.HasSuffix(name, ".egg-info") || strings.HasSuffix(name, ".dist-info")
}

// ScannedFile is one text file read during a walk, ready for analyzers to
// inspect. Only text files are included; walkFiles skips binaries and
// oversized files entirely.
type ScannedFile struct {
	// RelPath is the file's path relative to the scanned repo root, using
	// forward slashes regardless of host OS.
	RelPath string
	// AbsPath is the absolute path on disk, for an analyzer that needs to
	// re-read or reference the file outside of Content/Lines.
	AbsPath string
	// Content is the file's raw text content.
	Content string
	// Lines is Content split on "\n". Lines[i] is reported as line i+1
	// (1-based), matching how editors and stack traces number lines.
	Lines []string
}

// walkFiles reads every eligible text file under repoDir once, so analyzers
// share a single read/walk pass instead of each re-walking the tree. It
// returns the scanned files plus a list of non-fatal skip reasons (unreadable
// files, stat errors); those never abort the walk. A missing or non-directory
// repoDir is a fatal error.
//
// SAFETY: this only ever reads file bytes with os.ReadFile; it never executes
// anything, matching the read-only trust tier of sandbox.DetectEcosystem.
func walkFiles(repoDir string) ([]ScannedFile, []string, error) {
	info, err := os.Stat(repoDir)
	if err != nil {
		return nil, nil, fmt.Errorf("stat repo dir: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("repo path %q is not a directory", repoDir)
	}

	var files []ScannedFile
	var skipped []string

	walkErr := filepath.WalkDir(repoDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		if d.IsDir() {
			if path != repoDir && (skipDirNames[d.Name()] || isGeneratedMetadataDir(d.Name())) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		if fi.Size() == 0 || fi.Size() > maxScanFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		if looksBinary(data) {
			return nil
		}
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			rel = path
		}
		content := string(data)
		files = append(files, ScannedFile{
			RelPath: filepath.ToSlash(rel),
			AbsPath: path,
			Content: content,
			Lines:   strings.Split(content, "\n"),
		})
		return nil
	})
	if walkErr != nil {
		return nil, skipped, fmt.Errorf("walk repo dir: %w", walkErr)
	}
	return files, skipped, nil
}

// looksBinary reports whether data appears to be a binary file (a NUL byte in
// the first 512 bytes, the same heuristic git and file(1) use). Binary files
// cannot carry meaningful text-pattern findings and would otherwise waste
// time or produce noise from misinterpreted bytes.
func looksBinary(data []byte) bool {
	n := 512
	if len(data) < n {
		n = len(data)
	}
	return bytes.IndexByte(data[:n], 0) != -1
}

// isMinifiedOrVendorPath reports whether relPath looks like a checked-in
// minified or vendored bundle. Minification alone is normal and not evidence
// of anything; the generic long-line/entropy check excludes these paths so a
// legitimate bundled dependency does not flood the report. The specific
// signature checks in regex.go do NOT use this exclusion: a packer signature
// or an obfuscator fingerprint is suspicious regardless of minification.
func isMinifiedOrVendorPath(relPath string) bool {
	p := filepath.ToSlash(relPath)
	if strings.HasSuffix(p, ".min.js") || strings.HasSuffix(p, ".bundle.js") {
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "dist" || seg == "build" {
			return true
		}
	}
	return false
}

// isSVGPath reports whether relPath is an SVG file. SVG path/viewBox
// attributes are legitimately one long line of numeric coordinate data,
// which reads as a long, moderately-high-entropy line without being an
// obfuscated payload -- the same false-positive shape isMinifiedOrVendorPath
// exists to avoid, so entropy.go excludes SVG the same way.
//
// This exclusion is conditional, not blanket: unlike prose, SVG can execute
// (inline <script>, onload=/onclick= handlers -- a real XSS vector), so
// entropy.go only honors this exclusion when the file has no <script> tag
// (see svgScriptTagRe there); a script-carrying SVG loses it. Either way, the
// specific signature checks in regex.go are NOT extension-scoped and keep
// scanning .svg content unfiltered, and .svg is deliberately absent from
// proseExtensions in analyze.go (which would cap it at Info, treating it as
// inert).
func isSVGPath(relPath string) bool {
	return strings.EqualFold(filepath.Ext(relPath), ".svg")
}
