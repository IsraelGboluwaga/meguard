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

Releases are cut with GitHub Actions plus goreleaser. The config lives in
`.goreleaser.yaml` and the workflow in `.github/workflows/release.yml`. On a
semver tag push (`v*`) the pipeline runs `go build ./...` and `go test ./...`,
builds cross-platform binaries (macOS + Linux, amd64 + arm64), writes a
`checksums.txt` (SHA256), publishes a GitHub Release with the archives attached,
and pushes a Homebrew formula to the tap repo.

Current variant: the release ships the PURE static (`CGO_ENABLED=0`) binary,
which is meguard's only meaningful variant today (there is no cgo code yet). When
scan lands with the tree-sitter AST analyzer, add a second `builds` entry with
`CGO_ENABLED=1` and `-tags cgo` (per-OS runners for the C toolchain) and make the
full cgo binary the primary download, keeping the pure build as the
zero-dependency alternative.

### One-time setup before the first release

1. Create the tap repository `github.com/IsraelGboluwaga/homebrew-tap` (public,
   empty is fine). Homebrew derives the tap name from the `homebrew-` prefix.
2. Create a Personal Access Token that can push to that tap repo (a fine-grained
   token with Contents: read/write on `homebrew-tap`, or a classic token with
   `repo` scope). The default `GITHUB_TOKEN` cannot push to a different repo.
3. Add it to THIS repo as an Actions secret named `HOMEBREW_TAP_GITHUB_TOKEN`
   (Settings > Secrets and variables > Actions).
4. Add a `LICENSE` file and set `brews[0].license` in `.goreleaser.yaml` to the
   matching SPDX id (for example `MIT`). Homebrew's audit expects a license.
   This is currently commented out with a TODO.

### Cutting a release

    git tag v0.1.0
    git push origin v0.1.0

The workflow does the rest. To validate the config locally before tagging:

    goreleaser check
    goreleaser release --snapshot --clean   # dry run, no publish

## Versioning stance

Stay on 0.x until the CLI surface and any JSON schema (scan output) stabilize.
Breaking changes are expected during 0.x. Follow semver once 1.0 is cut. The
release version is injected into the binary via ldflags and shown by
`meguard --version`.

## Future distribution

- A `curl | sh` installer script that downloads the right binary and verifies its
  checksum against `checksums.txt`.
- Once scan ships: publish both build variants (full cgo primary, pure static
  alternative) in the same release.

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
