package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
)

// prefetchOutcome reports what the prefetch (leg 1 of the two-phase install) did,
// so runSandbox can pick the sandbox install command and print an honest status
// line.
type prefetchOutcome struct {
	// Attempted is true when the ecosystem defines a PrefetchCmd and prefetch was
	// not disabled. When false the run is single-phase and Detail says why.
	Attempted bool
	// OK is true when prefetch completed and the offline install is usable. Only
	// meaningful when Attempted is true.
	OK bool
	// Detail is a short human note: the skip reason, or the failure summary.
	Detail string
}

// runPrefetch runs the ecosystem's dependency prefetch (leg 1 of the two-phase
// install) inside a hardened, networked, no-host-mount CONTAINER via
// sandbox.RunPrefetch, then leaves the populated cache in repoDir for the sealed
// offline install to consume. The prefetch downloads the full dependency tree
// without running any repo or dependency lifecycle script (`--ignore-scripts`),
// so no untrusted code runs, and because the container has no host mounts a
// hostile local dependency spec (`file:`, `overrides`, ...) can only ever reach
// the container's own filesystem, never the host's.
//
// Prefetch is best-effort: any failure returns Attempted=true, OK=false with a
// Detail, and the caller falls back to the single-phase (fail-fast) install.
// repoDir must be a directory meguard owns (a clone temp or a staged copy) so the
// copied-back cache never lands in the user's working tree.
// out receives the prefetch command's own streamed output (the npm log). In a
// compact run the caller passes a buffer it discards on success and flushes only
// if prefetch fails, so a clean prefetch's npm noise never reaches the terminal;
// diag is meguard's own diagnostic channel (cleanup failures) and must always be
// the real stderr, even when out is buffered.
func runPrefetch(ctx context.Context, runner sandbox.DockerRunner, eco sandbox.Ecosystem, repoDir string, timeout time.Duration, out, diag io.Writer) prefetchOutcome {
	if len(eco.PrefetchCmd) == 0 {
		return prefetchOutcome{Attempted: false, Detail: fmt.Sprintf("%s: no prefetch (single-phase; sandbox has no network)", eco.Name)}
	}

	// The prefetch command runs INSIDE the container, so the cache path is the
	// in-container path, not a host path.
	args := substituteCacheDir(eco.PrefetchCmd, sandbox.ContainerCacheDir)

	err := runner.RunPrefetch(ctx, sandbox.PrefetchOptions{
		Image:       eco.Image,
		RepoDir:     repoDir,
		InstallArgs: args,
		Timeout:     timeout,
		// The prefetch tool's own output (the npm log) goes to out, which a compact
		// run buffers and discards on success. Cleanup diagnostics go to diag, which
		// is always the real stderr, so a `docker rm -f` failure is never lost.
		Stdout: out,
		Stderr: out,
		Diag:   diag,
	})
	if err != nil {
		return prefetchOutcome{Attempted: true, OK: false, Detail: fmt.Sprintf("prefetch failed (%v); falling back to single-phase install", err)}
	}

	// Defense in depth: ensure no host-built node_modules is carried into the
	// sealed sandbox. RunPrefetch copies out only the cache, but a stale
	// node_modules from a re-used staging dir should never ride along; the sealed
	// install rebuilds it fresh from the cache so every lifecycle script runs
	// there. Best effort.
	if rmErr := os.RemoveAll(filepath.Join(repoDir, "node_modules")); rmErr != nil {
		fmt.Fprintf(diag, "meguard: could not clear staged node_modules before sandbox install: %v\n", rmErr)
	}

	return prefetchOutcome{Attempted: true, OK: true, Detail: fmt.Sprintf("%s dependencies prefetched in a networked, no-host-mount container (no scripts run)", eco.Name)}
}

// substituteCacheDir returns a copy of args with every CacheDirPlaceholder token
// replaced by cacheDir (the in-container cache path).
func substituteCacheDir(args []string, cacheDir string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == sandbox.CacheDirPlaceholder {
			out[i] = cacheDir
			continue
		}
		out[i] = a
	}
	return out
}

// stageForMutation returns a directory meguard may safely write into (prefetch
// copies the cache back there) plus a cleanup and an owned flag. When the
// resolved repo is already meguard-owned (a git clone temp), it is returned
// as-is. When it is the user's own working tree (a local path used in place), it
// is COPIED into a fresh temp dir so meguard never mutates the user's files.
func stageForMutation(repoDir string, owned bool) (string, func(), error) {
	if owned {
		return repoDir, func() {}, nil
	}
	dst, err := os.MkdirTemp("", "meguard-stage-")
	if err != nil {
		return "", func() {}, fmt.Errorf("create staging dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dst) }
	if err := copyDir(repoDir, dst); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("stage repo copy: %w", err)
	}
	return dst, cleanup, nil
}

// copyDir recursively copies the contents of src into an existing dst directory.
// It copies regular files and directories and recreates symlinks verbatim (it
// does not follow them), so a staged copy mirrors the source without escaping it.
func copyDir(src, dst string) error {
	root := filepath.Clean(src)
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		switch {
		case d.IsDir():
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(target, info.Mode().Perm())
		case d.Type()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case d.Type().IsRegular():
			return copyFile(path, target)
		default:
			// Skip devices, sockets, fifos: they carry no repo content.
			return nil
		}
	})
}

// copyFile copies a single regular file from src to dst, preserving mode bits.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
