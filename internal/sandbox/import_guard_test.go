package sandbox_test

import (
	"os/exec"
	"strings"
	"testing"
)

// sandboxPkg is the package under test.
const sandboxPkg = "github.com/IsraelGboluwaga/meguard/internal/sandbox"

// forbiddenSubstrings are import-path fragments that must never appear in the
// sandbox package's transitive dependencies. scan and its analyzers live under
// these; the run/sandbox path must stay structurally independent of them.
var forbiddenSubstrings = []string{
	"/internal/analyze",
	"/analyzer",
	"tree-sitter",
	"tree_sitter",
	"go-tree-sitter",
}

// TestSandboxDoesNotImportAnalyze is the architecture guard test.
//
// WHAT IT ASSERTS: none of the transitive dependencies of internal/sandbox
// belongs to scan, an analyzer, or tree-sitter. "internal/sandbox NEVER
// imports analyze" is thereby enforced structurally rather than by
// convention. This is narrower than "run never imports analyze": cmd (the
// CLI package "run" and "scan" live in) DOES import internal/analyze, by
// design, to combine detection with containment in "meguard run" and to run
// detection alone in "meguard scan". What must stay independent is the
// sandbox's containment guarantee, not the CLI layer above it.
//
// FAILURE DIRECTION: this test PASSES today (no analyze package exists yet and
// sandbox depends only on the standard library). It will FAIL the moment
// internal/sandbox gains a transitive dependency on any analyzer package, for
// example if someone adds `import ".../internal/analyze"` to a sandbox source
// file. The fix is to remove that import, not to relax this test.
//
// It is implemented with `go list -deps` so it stays simple and fast.
func TestSandboxDoesNotImportAnalyze(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", sandboxPkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s failed: %v\n%s", sandboxPkg, err, out)
	}

	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range forbiddenSubstrings {
			if strings.Contains(dep, bad) {
				t.Errorf("sandbox has a forbidden transitive dependency %q (matched %q).\n"+
					"internal/sandbox MUST NOT import analyze or any analyzer; purity is structural.",
					dep, bad)
			}
		}
	}
}
