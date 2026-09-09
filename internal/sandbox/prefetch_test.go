package sandbox

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// tarBytes builds an in-memory tar stream from the given entries for untarInto
// tests. A non-empty link makes the entry a symlink with that target.
func tarBytes(t *testing.T, entries []tar.Header, bodies map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		hdr := h
		if body, ok := bodies[hdr.Name]; ok {
			hdr.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if body, ok := bodies[hdr.Name]; ok {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestUntarIntoExtractsFilesAndDirs confirms the normal case: directories and
// regular files are materialized with their content.
func TestUntarIntoExtractsFilesAndDirs(t *testing.T) {
	dest := t.TempDir()
	data := tarBytes(t, []tar.Header{
		{Name: ".meguard-cache/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: ".meguard-cache/blob.txt", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "package-lock.json", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{
		".meguard-cache/blob.txt": "cached-bytes",
		"package-lock.json":       "{}",
	})

	if err := untarInto(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("untarInto error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, ".meguard-cache", "blob.txt"))
	if err != nil || string(got) != "cached-bytes" {
		t.Errorf("blob.txt = %q, %v; want %q", got, err, "cached-bytes")
	}
	if _, err := os.Stat(filepath.Join(dest, "package-lock.json")); err != nil {
		t.Errorf("package-lock.json not extracted: %v", err)
	}
}

// TestUntarIntoRejectsTraversal confirms a crafted "../" entry name is refused
// rather than written outside destDir.
func TestUntarIntoRejectsTraversal(t *testing.T) {
	dest := t.TempDir()
	data := tarBytes(t, []tar.Header{
		{Name: "../escape.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"../escape.txt": "pwned"})

	if err := untarInto(bytes.NewReader(data), dest); err == nil {
		t.Fatal("untarInto accepted a ../ traversal entry, want an error")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.txt")); err == nil {
		t.Error("traversal entry was written outside destDir")
	}
}

// TestUntarIntoSkipsSymlinks is the Finding-1 regression guard: a symlink entry
// pointing at an absolute host path (CWE-59 arbitrary-symlink-plant) must NOT be
// recreated on the host.
func TestUntarIntoSkipsSymlinks(t *testing.T) {
	dest := t.TempDir()
	data := tarBytes(t, []tar.Header{
		{Name: ".meguard-cache/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: ".meguard-cache/leak", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: ".meguard-cache/rel", Typeflag: tar.TypeSymlink, Linkname: "../../../../etc/passwd"},
	}, nil)

	if err := untarInto(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("untarInto error: %v", err)
	}
	for _, name := range []string{"leak", "rel"} {
		p := filepath.Join(dest, ".meguard-cache", name)
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("symlink %q was recreated on the host; it must be skipped", name)
		}
	}
}
