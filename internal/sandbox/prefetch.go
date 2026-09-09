package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PrefetchOptions configures a single containerized prefetch (leg 1 of the
// two-phase install).
type PrefetchOptions struct {
	// Image is the container image to run the prefetch in. It is the SAME image
	// as the sealed sandbox, so the fetched cache matches the platform the offline
	// install will run on.
	Image string
	// RepoDir is the host staging dir. Its contents are copied INTO the prefetch
	// container's /repo tmpfs, and the populated npm cache is copied back OUT into
	// RepoDir so the normal tar-into-sandbox path carries it to the sealed install.
	RepoDir string
	// InstallArgs is the prefetch command run inside the container, e.g.
	// `npm install --ignore-scripts ... --cache <ContainerCacheDir>`. It must run
	// no repo lifecycle scripts (that is what makes a networked container safe).
	InstallArgs []string
	// Timeout bounds the in-container prefetch exec. Zero means no timeout.
	Timeout time.Duration
	// Stdout and Stderr receive the prefetch command's streamed output. A compact
	// CLI run buffers these and discards them on success (the npm log is noise on a
	// clean prefetch), so they must carry ONLY the command's own output.
	Stdout io.Writer
	Stderr io.Writer
	// Diag receives meguard's OWN operational diagnostics for the prefetch (the
	// container cleanup / `docker rm -f` failure), separate from the command output
	// above. It must point at the real stderr even when Stdout/Stderr are buffered,
	// so a cleanup failure is never swallowed by a discarded buffer on an otherwise
	// successful prefetch (mirrors ExecuteOptions.Diag; see decision 0017). When
	// nil it falls back to Stderr.
	Diag io.Writer
}

// RunPrefetch runs the dependency prefetch inside a hardened, NETWORKED,
// no-host-mount container and copies the resulting npm cache back into
// opts.RepoDir. The container is force-removed on every path.
//
// Lifecycle: create (hardened + bridge network) -> start -> copy repo into tmpfs
// -> exec `npm install --ignore-scripts ...` -> copy the cache OUT -> rm -f.
//
// SAFETY: see prefetchCreateArgs. The container has a network but runs no repo
// code (--ignore-scripts), so the untrusted repo can never use it; npm fetches
// inert tarballs that only ever execute later inside the sealed sandbox. With no
// host mounts, a malicious local dependency spec (`file:`, `overrides`, ...)
// resolves against the container's own filesystem, so it can never read a host
// file. Only the npm cache is copied out, never node_modules, so even a
// container-local file read cannot leave the container.
func (d DockerRunner) RunPrefetch(ctx context.Context, opts PrefetchOptions) error {
	p := Profile{Image: opts.Image}.Normalize()

	diag := opts.Diag
	if diag == nil {
		diag = opts.Stderr
	}

	name, err := containerName()
	if err != nil {
		return err
	}
	name = "meguard-prefetch-" + strings.TrimPrefix(name, "meguard-")

	create := exec.CommandContext(ctx, d.bin(), prefetchCreateArgs(name, p)...)
	create.Stdout = io.Discard
	var cErr bytes.Buffer
	create.Stderr = &cErr
	if err := create.Run(); err != nil {
		return fmt.Errorf("docker create prefetch container: %w: %s", err, strings.TrimSpace(cErr.String()))
	}
	// Guarantee removal on every path (success, failure, panic, Ctrl-C), using a
	// detached, time-bounded context so a cancelled run still cleans up.
	defer removeDetached(d, name, diag)

	if err := d.Start(ctx, name); err != nil {
		return err
	}
	if err := d.CopyInto(ctx, name, opts.RepoDir, "/repo"); err != nil {
		return fmt.Errorf("copy repo into prefetch container: %w", err)
	}

	execCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	code, err := d.Exec(execCtx, name, opts.InstallArgs, opts.Stdout, opts.Stderr)
	if err != nil {
		if opts.Timeout > 0 && errors.Is(execCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("%w after %s", ErrInstallTimeout, opts.Timeout)
		}
		return fmt.Errorf("run prefetch command: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("prefetch command exited %d", code)
	}

	// Copy the populated cache (and the lockfile, for a deterministic offline
	// resolution) back out to the host staging dir. node_modules is deliberately
	// left behind in the container (a fresh offline install in the sealed sandbox
	// rebuilds it from the cache, which is what makes every lifecycle script run
	// there where its egress is contained).
	if err := d.copyCacheOut(ctx, name, opts.RepoDir); err != nil {
		return fmt.Errorf("copy prefetched cache out of container: %w", err)
	}
	return nil
}

// copyCacheOut streams the prefetched cache (and any generated lockfile) OUT of
// the container's /repo tmpfs into destDir on the host.
//
// It uses a `tar` process inside the container piped to an in-process extractor,
// NOT `docker cp`: /repo is a tmpfs mount, and `docker cp` cannot read from tmpfs
// or volume mounts (only the container's layered rootfs), so it reports the path
// as "not found". This mirrors CopyInto, which tars INTO the tmpfs for the same
// reason. Only the cache dir and lockfiles are named, so nothing else npm wrote
// (node_modules, logs) is carried to the host.
func (d DockerRunner) copyCacheOut(ctx context.Context, id, destDir string) error {
	// $(ls ...) conditionally includes the lockfiles only if present, so tar does
	// not fail on a repo that produced none. The cache dir is always present after
	// a successful prefetch.
	script := "cd /repo && tar -cf - " + CacheDirName + " $(ls package-lock.json npm-shrinkwrap.json 2>/dev/null)"
	cmd := exec.CommandContext(ctx, d.bin(), "exec", id, "sh", "-c", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start cache export: %w", err)
	}
	untarErr := untarInto(stdout, destDir)
	if waitErr := cmd.Wait(); waitErr != nil {
		return fmt.Errorf("cache export tar: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return untarErr
}

// untarInto extracts a tar stream (an npm cache tree plus any lockfiles) into
// destDir. Only directories and regular files are materialized.
//
// SECURITY: the tar is produced INSIDE the prefetch container over a subtree
// (.meguard-cache + lockfiles) whose bytes originate from the untrusted repo, so
// its entries are attacker-influenced and this extraction runs on the HOST. Two
// guards keep it from writing outside destDir:
//   - Every entry NAME is validated to resolve within destDir, rejecting a
//     crafted "../" traversal.
//   - SYMLINK entries are SKIPPED entirely, never recreated. An npm cache and
//     lockfiles never legitimately contain symlinks, and recreating one with an
//     attacker-chosen target (e.g. .meguard-cache/x -> /etc/passwd or ~/.ssh) is
//     an arbitrary host-symlink-plant primitive (CWE-59). Skipping removes it
//     structurally; there is nothing here a symlink is needed for.
//
// Hardlinks, devices, and fifos are likewise skipped; the npm cache has none.
func untarInto(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)
	cleanDest := filepath.Clean(destDir)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read cache tar: %w", err)
		}
		target := filepath.Join(cleanDest, hdr.Name)
		if target != cleanDest && !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("cache tar entry escapes destination: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			// Skip symlinks (see SECURITY above), hardlinks, devices, and fifos:
			// the npm cache and lockfiles are only directories and regular files.
		}
	}
}
