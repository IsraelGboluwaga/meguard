# Changelog

All notable changes to meguard are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
meguard stays on 0.x until the CLI surface and any JSON schema stabilize.

## [Unreleased]

### Added

- `meguard run <repo-url-or-path>` executes an untrusted repo inside a
  locked-down container sandbox, end to end.
  - Lifecycle: `docker create` (hardened) -> `docker cp` repo into a tmpfs ->
    `docker start` -> `docker exec` install command (streamed) -> `docker rm -f`
    (always).
  - Accepts a git URL (cloned to a temp dir, always cleaned up) or a local path
    (copied, never bind mounted).
  - `--image` (default `node:20-slim`) and `--cmd` (default `npm install`) are
    the only two ecosystem-specific values. Auto-detection is out of scope.
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
