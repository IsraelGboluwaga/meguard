package analyze

// noopAnalyzer is the AST analyzer's current implementation on BOTH build
// variants. A real tree-sitter grammar is future work, out of scope for this
// slice (it would pull in cgo dependencies and per-language grammars well
// beyond what catching the obfuscated-payload and exfiltration patterns in
// manifest.go/entropy.go/regex.go needs). This labels the absence explicitly
// rather than silently reporting a clean AST pass: see CLAUDE.md's scan
// architecture decision. ast_cgo.go and ast_nocgo.go set the reason string,
// proving the build-tag machinery selects between them correctly even though
// both currently produce a no-op.
type noopAnalyzer struct {
	reason string
}

func (noopAnalyzer) Name() string { return "ast" }

func (noopAnalyzer) Analyze(files []ScannedFile) ([]Finding, error) {
	return nil, nil
}

// newASTAnalyzer returns the AST analyzer for this build. See ast_cgo.go
// (built with -tags cgo) and ast_nocgo.go (the default, pure build) for the
// build-tag-selected reason.
func newASTAnalyzer() noopAnalyzer {
	return noopAnalyzer{reason: astDisabledReason}
}
