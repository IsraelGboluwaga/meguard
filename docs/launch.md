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
stream the repo into the sandbox tmpfs. The defaults (node:22-slim) and other
Debian/Alpine-based images include it.

For a node repo, `run` also does a containerized dependency prefetch by
default (the first leg of the two-phase install; see README.md and
docs/documentation.md): a throwaway, hardened container with a network runs
`npm install --ignore-scripts`. This needs the same container runtime already
required above, plus outbound network access from that runtime to the public
npm registry (`registry.npmjs.org`). No local `npm` is needed on the host at
all; the prefetch runs entirely inside the container. If the runtime cannot
reach the registry, prefetch fails and `run` automatically falls back to the
single-phase install, so this is not a hard requirement, just something that
changes what gets exercised. `--no-prefetch` skips it outright.

### To build meguard

- Go 1.24 or newer.
- Neither variant needs a C toolchain today. Scan is implemented
  (`internal/analyze`: manifest, entropy, regex), but its AST analyzer is
  still a labeled no-op behind the cgo build tag on BOTH variants (no package
  in the repo imports cgo yet; see docs/documentation.md's Scan architecture
  section). A C toolchain and tree-sitter build requirements per platform
  will become necessary for the full (cgo) variant once a real tree-sitter
  grammar is wired in.

## Build from source (both variants)

Two variants ship under the same binary name and the same commands.

Pure static variant (zero-dependency; the `run` binary is cgo-free; scan runs
manifest, entropy, and regex analysis; AST is a labeled no-op):

    CGO_ENABLED=0 go build -o meguard .

Full cgo variant (the build-tag seam scan's AST analyzer will use once a real
tree-sitter grammar is wired in; today it is functionally identical to the
pure variant, still a labeled no-op with a different disabled-reason string):

    # macOS: needs Xcode command line tools
    # Linux: needs gcc/clang and the platform C headers
    CGO_ENABLED=1 go build -tags cgo -o meguard .

Verify the pure build is genuinely cgo-free:

    go version -m meguard | grep CGO_ENABLED    # expect: CGO_ENABLED=0

## go install

    go install github.com/IsraelGboluwaga/meguard@latest

This produces the pure (CGO_ENABLED=0 by default on most setups) variant. For the
full variant, build from source with `-tags cgo` as above.

## Continuous integration

Every push and pull request against `main` runs `.github/workflows/ci.yml` on
`ubuntu-latest`: `gofmt -l` (fails on unformatted files), `go mod verify`,
`go build ./...`, `go vet ./...`, `go test ./...`, then a dedicated step that
rebuilds the pure static binary and checks `go version -m meguard` reports
`CGO_ENABLED=0`, so the "run binary stays pure Go" rule (CLAUDE.md coding
standards) is enforced on every change, not just caught later at release time.
This is separate from, and does not trigger, the tag-triggered release
workflow below.

## Release automation

Releases are cut with GitHub Actions plus goreleaser. The config lives in
`.goreleaser.yaml` and the workflow in `.github/workflows/release.yml`. On a
semver tag push (`v*`) the pipeline runs `go build ./...` and `go test ./...`,
builds cross-platform binaries (macOS + Linux, amd64 + arm64), writes a
`checksums.txt` (SHA256), publishes a GitHub Release with the archives attached,
and pushes a Homebrew formula to the tap repo.

Current variant: the release ships the PURE static (`CGO_ENABLED=0`) binary.
This is still meguard's only meaningful release variant: scan is implemented
(manifest, entropy, regex), but its AST analyzer is a labeled no-op on both
build tags (no package imports cgo yet), so a cgo build today is functionally
identical to the pure build. When a real tree-sitter grammar is wired in
behind the existing cgo build tag (see docs/documentation.md's Scan
architecture section), add a second `builds` entry with `CGO_ENABLED=1` and
`-tags cgo` (per-OS runners for the C toolchain) and make the full cgo binary
the primary download, keeping the pure build as the zero-dependency
alternative.

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
- Once a real tree-sitter grammar is wired into the AST analyzer (scan itself
  has already shipped; see docs/documentation.md): publish both build variants
  (full cgo primary, pure static alternative) in the same release.

## Verify after install

    meguard --help
    meguard run --help
    meguard scan --help

    # Scan alone, no container, no Docker dependency at all:
    meguard scan https://github.com/octocat/Hello-World.git

    # End to end against a known-safe repo, with a compatible runtime running:
    meguard run https://github.com/octocat/Hello-World.git

Expected for `run` (default, compact): a one-line header, then a status
checklist (`sandbox`, `prefetch`, `install`, `scan`, `egress`, `secrets`), a
"Top findings" block if scan found anything High/Critical, and a single
`RESULT: ...` sentence. The raw install log is only shown if the install
exited non-zero. Note that Hello-World has no package.json, so `npm install`
reports a non-zero install exit code (and its log is printed); that is the
sandboxed command's outcome, not a meguard failure. Point `run` at a repo
with a package.json (or pass `--cmd`) to see a zero install exit code and,
for a node repo, the `prefetch` line report a successful containerized fetch
(or a stated fallback reason if it declined or failed). Pass `-v`/`--verbose`
for the full report: a pre-run notice listing the active protections, a
STATIC SCAN section (skip scanning entirely with `--no-scan`), streamed
sandbox output under a labeled section, and a result with the install exit
code and the "0 host secrets exposed (by construction)" line.

`--no-prefetch` restores the single-phase node install (no containerized
fetch; the sandbox has no network, so dependency lifecycle scripts do not
run). `--timeout` (default `2m`, `0` disables) bounds both the containerized
prefetch and the in-sandbox install; on install-side timeout the run reports
`sandbox.ErrInstallTimeout`
and cleanup still runs.

Expected for `scan` (default, compact): a one-line header, a status line, and
a "Top findings" block; `scan` exits non-zero only if any High/Critical
finding was reported. Pass `-v`/`--verbose` for a STATIC SCAN section with a
files-scanned count, the AST-disabled line (labeled, never silent), and
either "findings: none" or a list of every finding.

If meguard reports it cannot reach the runtime, confirm your Docker-compatible
runtime is installed and running (for example `orbstack status`, `colima status`,
`podman info`, or `docker info`).
