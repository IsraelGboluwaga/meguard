//go:build cgo

package analyze

// astDisabledReason states why the AST analyzer is inactive in a cgo build:
// the build-tag machinery is live (this file compiled instead of
// ast_nocgo.go, so a cgo toolchain IS available), but no tree-sitter grammar
// is wired in yet in this slice. manifest, entropy, and regex analyzers still
// ran; their coverage is not reduced by AST's absence.
const astDisabledReason = "AST analysis is not yet implemented for this build (cgo is available, but no tree-sitter grammar is wired in yet); manifest, entropy, and regex analyzers still ran"
