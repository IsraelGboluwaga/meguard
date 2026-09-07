package sandbox

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteRepoTar checks the properties CopyInto relies on: the root entry is
// never emitted (so extraction cannot touch the container mount point), every
// entry is owned by the sandbox user, names are slash-separated, and regular
// file contents survive.
func TestWriteRepoTar(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "index.js"), []byte("console.log(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := writeRepoTar(&buf, root); err != nil {
		t.Fatalf("writeRepoTar error: %v", err)
	}

	entries := map[string]string{} // name -> content
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}

		if hdr.Name == "." || hdr.Name == "./" || hdr.Name == "" {
			t.Errorf("tar contains a root entry %q; extraction must not touch the mount point", hdr.Name)
		}
		if hdr.Uid != sandboxUID || hdr.Gid != sandboxGID {
			t.Errorf("entry %q owned by %d:%d, want %d:%d", hdr.Name, hdr.Uid, hdr.Gid, sandboxUID, sandboxGID)
		}
		if filepath.ToSlash(hdr.Name) != hdr.Name {
			t.Errorf("entry name %q is not slash-separated", hdr.Name)
		}

		body, _ := io.ReadAll(tr)
		entries[hdr.Name] = string(body)
	}

	if _, ok := entries["package.json"]; !ok {
		t.Errorf("missing package.json; got entries %v", keys(entries))
	}
	if got := entries["src/index.js"]; got != "console.log(1)\n" {
		t.Errorf("src/index.js content = %q, want the source line", got)
	}
	if _, ok := entries["src/"]; !ok {
		t.Errorf("missing directory entry src/; got entries %v", keys(entries))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestTarExtractArgs pins the in-container extractor argv.
func TestTarExtractArgs(t *testing.T) {
	got := tarExtractArgs("cid", "/repo")
	want := []string{"exec", "-i", "cid", "tar", "-xf", "-", "-C", "/repo"}
	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	}
}
