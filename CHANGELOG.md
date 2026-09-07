# Changelog

All notable changes to meguard are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
meguard stays on 0.x until the CLI surface and any JSON schema stabilize.

## [Unreleased]

### Added

- Ecosystem auto-detection (`sandbox.DetectEcosystem` in
  `internal/sandbox/detect.go`): `run` inspects the repo's top-level manifest
  files and picks the image and install command when `--image` / `--cmd` are
  unset. Node (`package.json` and lockfiles) maps to `node:20-slim` +
  `npm install`; Python (`requirements.txt` -> `pip install --user -r
  requirements.txt`, else `pyproject.toml`/`setup.py`/`setup.cfg`/`Pipfile` ->
  `pip install --user .`) maps to `python:3.12-slim`. Node and Python are the
  only ecosystems detected for now; anything else falls back to the locked-down
  defaults. Precedence: node over python, and `requirements.txt` over a project
  manifest. An explicit flag always wins. Detection only reads file existence
  (no repo code runs; invariant 1) and only supplies the RELAX values (never a
  security control; invariant 3). The pre-run notice now prints the detected
  ecosystem. Table-driven `TestDetectEcosystem` covers the mapping and
  precedence.
- `--runtime` flag on `meguard run`: selects the Docker-compatible CLI that
  enforces the sandbox (default `docker`; e.g. `--runtime podman` for a rootless
  runtime). The daemon is the trust boundary, so a rootless runtime shrinks the
  blast radius of a container escape from host root to an unprivileged user. The
  pre-run notice now names the runtime it is trusting.

### Security

- `git clone` on the host now passes `--` before the source
  (`git clone --depth 1 -- <source> <dir>`) so a source beginning with `-` can
  never be parsed as a git option. Defense in depth on top of the existing
  `isGitURL` gate, on the one host command that touches an attacker-controlled
  string.

- `meguard run <repo-url-or-path>` executes an untrusted repo inside a
  locked-down container sandbox, end to end.
  - Lifecycle: `docker create` (hardened) -> `docker cp` repo into a tmpfs ->
    `docker start` -> `docker exec` install command (streamed) -> `docker rm -f`
    (always).
  - Accepts a git URL (cloned to a temp dir, always cleaned up) or a local path
    (copied, never bind mounted).
  - `--image` and `--cmd` are the only two ecosystem-specific values; when unset
    they are auto-detected from the repo's manifests (see below), else fall back
    to `node:20-slim` / `npm install`.
  - Pre-run notice listing active protections; streamed sandbox output; a result
    with the install exit code and "0 host secrets exposed (by construction)".
- Hardening on the container: `--user 1000:1000`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--read-only`, `--tmpfs /repo:exec`,
  `--tmpfs /home/sandbox`, `--tmpfs /tmp`, `--pids-limit 512`, `--memory 2g`,
  `--cpus 2`, `--network none`, `-w /repo`, `-e HOME=/home/sandbox`.
- `internal/sandbox`: `Runner` interface, `DockerRunner` (docker CLI via
  os/exec), and `Profile` whose zero value is fully locked down (fields only
  relax non-security defaults).
- Cleanup guarantee: the container is force-removed on success, install failure,
  panic, or Ctrl-C, via a deferred detached-context `Remove` plus
  `signal.NotifyContext` in `main`.
- Runtime preflight: before cloning or printing the pre-run notice, `run` checks
  that a Docker-compatible runtime is reachable (`docker info`). If not, it fails
  fast with actionable guidance that names OrbStack, Colima, and Podman and notes
  Docker Desktop is not required, instead of a raw daemon connection error after
  a misleading notice.
- Tests:
  - `TestCreateArgsHardening` argv contract test: fails if any hardening flag is
    removed or altered.
  - `TestSandboxDoesNotImportAnalyze` architecture guard: fails if
    `internal/sandbox` ever gains a transitive dependency on analyze or an
    analyzer.
  - Table-driven `TestProfileNormalize` and additional argv tests.
  - Orchestration and cleanup tests via a fake Runner (happy path, non-zero
    exit is not an error, Create-failure skips Remove, and Remove ALWAYS runs on
    copy/start/exec failure and on panic; invariant 5).
  - Runtime guidance test (`TestRuntimeUnavailableError`), CLI helper tests
    (`TestIsGitURL`, `TestResolveRepoLocalPath`, notice/result output), and
    `TestContainerName` / `TestDockerRunnerBinDefault`.
- Documentation of the future `scan` analyzer architecture (analyzers behind an
  `Analyzer` interface; pure-Go manifest/entropy/regex; AST/tree-sitter isolated
  behind cgo build tags with a labeled no-op fallback; two build variants).
- Docs and contract: CLAUDE.md, README.md, docs/documentation.md, docs/launch.md,
  docs/decisions.md, and subagent definitions under `.claude/agents/`.
- Release pipeline: `.goreleaser.yaml` and `.github/workflows/release.yml` build
  cross-platform pure-static binaries (macOS/Linux, amd64/arm64) with SHA256
  checksums on a `v*` tag, publish a GitHub Release, and push a Homebrew formula
  to the `IsraelGboluwaga/homebrew-tap` tap (enables `brew install`). Requires a
  one-time tap repo, a `HOMEBREW_TAP_GITHUB_TOKEN` secret, and a LICENSE (see
  docs/launch.md).
- `meguard --version`, with the version injected at release time via ldflags.

### Changed

- Copy mechanism and lifecycle order, forced by real end-to-end testing against
  a live runtime (OrbStack): Docker refuses `docker cp` into a `--read-only`
  container, so the repo is now streamed in as a deterministic in-process tar
  piped to a `tar` process inside the container (`docker exec -i`). The container
  is started before the copy (lifecycle: create, start, copy, exec). `/repo` is
  mounted `mode=1777` so the non-root user can write it. All hardening flags,
  including `--read-only`, are retained; the security property of invariant 2 is
  unchanged. The container image must provide `tar` (standard in Debian/Alpine).

### Notes

- The `run` binary is pure Go (no cgo) and ships as a single static file.
- Network is `--network none`, hardcoded for this slice; no egress.
- `--memory` and `--cpus` are conservative defaults that will become
  user-configurable.
- TODO: surface blocked-egress attempts once an inspecting proxy exists.
- scan, analyzers, and tree-sitter are NOT implemented in this slice.
