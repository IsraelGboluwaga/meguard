# meguard launch and deploy guide

Everything needed to build, release, and verify meguard.

## Prerequisites

### To run meguard

A Docker-COMPATIBLE runtime must be installed AND running on PATH. Docker Desktop
is NOT required. Any of these work with no code change:

- OrbStack (macOS) - lightweight, recommended.
- Colima (macOS/Linux) - lightweight, recommended.
- Podman (daemonless, rootless) - recommended for security; rootless removes the
  root-daemon trust boundary.
- Docker Engine / Docker Desktop.

Note the daemon trust boundary: the container daemon runs privileged and is a
trust boundary meguard relies on. Prefer Podman rootless where isolation matters
most. Stronger backends (gVisor, Firecracker) are on the roadmap.

The container image used by `run` must provide `tar`, which meguard uses to
stream the repo into the sandbox tmpfs. The defaults (node:20-slim) and other
Debian/Alpine-based images include it.

### To build meguard

- Go 1.24 or newer.
- For the full (cgo) variant only: a C toolchain and tree-sitter build
  requirements per platform (once scan lands). The pure variant needs no C
  toolchain.

## Build from source (both variants)

Two variants ship under the same binary name and the same commands.

Pure static variant (zero-dependency; the `run` binary is cgo-free; omits the
future AST analyzer):

    CGO_ENABLED=0 go build -o meguard .

Full cgo variant (adds the tree-sitter AST analyzer once scan exists):

    # macOS: needs Xcode command line tools
    # Linux: needs gcc/clang and the platform C headers
    CGO_ENABLED=1 go build -tags cgo -o meguard .

Verify the pure build is genuinely cgo-free:

    go version -m meguard | grep CGO_ENABLED    # expect: CGO_ENABLED=0

## go install

    go install github.com/IsraelGboluwaga/meguard@latest

This produces the pure (CGO_ENABLED=0 by default on most setups) variant. For the
full variant, build from source with `-tags cgo` as above.

## Release automation

Releases are cut with GitHub Actions plus goreleaser, producing cross-platform
binaries with SHA256 checksums. Both variants are published:

- The full cgo binary is the DEFAULT/PRIMARY download.
- The pure static binary is the zero-dependency ALTERNATIVE.

Sketch of the pipeline (to be committed under `.github/workflows/`):

- On a tag push (`v*`), run `go test ./...` and `go vet ./...`.
- Build the pure variant with `CGO_ENABLED=0` for each target OS/arch.
- Build the full variant with `CGO_ENABLED=1 -tags cgo` using per-platform C
  toolchains (native runners or cross-compilers).
- Generate SHA256 checksums for every artifact.
- Publish a GitHub Release with both variants attached, the cgo build listed
  first as the primary download and the pure build labeled as the
  zero-dependency alternative.

## Versioning stance

Stay on 0.x until the CLI surface and any JSON schema (scan output) stabilize.
Breaking changes are expected during 0.x. Follow semver once 1.0 is cut.

## Future distribution

- Homebrew tap (`brew install IsraelGboluwaga/tap/meguard`).
- A `curl | sh` installer script that downloads the right variant and verifies
  its checksum.

## Verify after install

    meguard --help
    meguard run --help

    # End to end against a known-safe repo, with a compatible runtime running:
    meguard run https://github.com/octocat/Hello-World.git

Expected: a pre-run notice listing the active protections, streamed sandbox
output under a labeled section, and a result with the install exit code and the
"0 host secrets exposed (by construction)" line. Note that Hello-World has no
package.json, so `npm install` reports a non-zero install exit code; that is the
sandboxed command's outcome, not a meguard failure. Point `run` at a repo with a
package.json (or pass `--cmd`) to see a zero install exit code.

If meguard reports it cannot reach the runtime, confirm your Docker-compatible
runtime is installed and running (for example `orbstack status`, `colima status`,
`podman info`, or `docker info`).
