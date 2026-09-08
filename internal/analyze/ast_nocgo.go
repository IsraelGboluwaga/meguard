//go:build !cgo

package analyze

// astDisabledReason states why the AST analyzer is inactive on the pure
// static build: it needs a cgo build with a tree-sitter grammar wired in
// (see CLAUDE.md's scan architecture decision), and this binary is the pure
// static (CGO_ENABLED=0) variant. manifest, entropy, and regex analyzers
// still ran; their coverage is not reduced by AST's absence.
const astDisabledReason = "AST analysis needs a cgo build (rebuild with -tags cgo); this binary is the pure static (CGO_ENABLED=0) variant, so AST is disabled; manifest, entropy, and regex analyzers still ran"
