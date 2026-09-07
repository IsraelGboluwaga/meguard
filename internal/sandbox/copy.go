package sandbox

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// sandboxUID and sandboxGID match the container user (--user 1000:1000). Repo
// files are written under this ownership so the non-root install command can
// read them and write alongside them (for example node_modules) in the tmpfs.
const (
	sandboxUID = 1000
	sandboxGID = 1000
)

// writeRepoTar walks srcDir and writes a deterministic tar stream of its
// CONTENTS to w. It deliberately never emits an entry for the root directory
// itself, so extraction never tries to change the ownership or mode of the
// container mount point (/repo), which is owned by root. It carries no host
// extended attributes or platform metadata, so extraction is clean and quiet.
//
// This is how meguard copies a repo INTO the container tmpfs. Docker refuses
// `docker cp` into a --read-only container, so the stream is extracted by a
// `tar` process running inside the container (see DockerRunner.CopyInto), which
// writes to the tmpfs mount and is not subject to the read-only rootfs guard.
func writeRepoTar(w io.Writer, srcDir string) error {
	tw := tar.NewWriter(w)
	root := filepath.Clean(srcDir)

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip the root itself; only its contents are archived.
		if path == root {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relativize %s: %w", path, err)
		}
		name := filepath.ToSlash(rel)

		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return fmt.Errorf("readlink %s: %w", path, err)
			}
		}

		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return fmt.Errorf("tar header for %s: %w", path, err)
		}
		hdr.Name = name
		if info.IsDir() {
			hdr.Name += "/"
		}
		// Own everything as the sandbox user; drop host name mappings.
		hdr.Uid, hdr.Gid = sandboxUID, sandboxGID
		hdr.Uname, hdr.Gname = "", ""

		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header for %s: %w", name, err)
		}

		// Only regular files carry content. Directories and symlinks are fully
		// described by their header. Anything else (devices, sockets, fifos) is
		// skipped by the header type and has no body to copy.
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("open %s: %w", path, err)
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				return fmt.Errorf("copy %s into tar: %w", name, err)
			}
			f.Close()
		}
		return nil
	})

	// Close flushes the archive footer. Report the first error encountered.
	closeErr := tw.Close()
	if walkErr != nil {
		return walkErr
	}
	if closeErr != nil {
		return fmt.Errorf("finalize tar stream: %w", closeErr)
	}
	return nil
}

// tarExtractArgs returns the argv for the in-container extractor: a `tar` that
// reads the stream from stdin and unpacks it into destPath inside the container.
func tarExtractArgs(id, destPath string) []string {
	return []string{"exec", "-i", id, "tar", "-xf", "-", "-C", destPath}
}
