# Changelog

All notable changes to meguard are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
meguard stays on 0.x until the CLI surface and any JSON schema stabilize.

## [Unreleased]

### Changed

- Egress inspection is now the DEFAULT for `meguard run` (previously opt-in via
  `--inspect-egress`, now removed). A plain `meguard run <repo>` logs every
  blocked outbound attempt. The new `--strict` flag drops to `--network none`
  (no network stack at all, no logs) for the hardest, fully-verified containment.
  Egress is denied in both modes. Because inspected mode needs a monitor image +
  NFLOG, the CLI FALLS BACK to `--network none` with a printed warning if the
  monitor cannot start (`sandbox.ErrMonitorUnavailable`), so `meguard run` keeps
  working everywhere and never silently loses containment. The library zero-value
  Profile still selects `--network none`, so invariant 3 is unchanged; CLAUDE.md
  invariant 4 is updated to "egress always denied, in one of two modes".
  - VERIFIED on Docker/OrbStack (real Linux kernel): hardcoded-IP SYNs logged and
    dropped, no leak to a sibling container on the bridge subnet, DNS captured by
    name, IPv6 sealed, clean run reports "0 attempts", monitor-unavailable falls
    back, no container leaks. Rootless runtimes not yet checked.
  - Fixes found during that verification: (1) Execute now waits ~1.2s
    (`monitorFlushDelay`) for tcpdump to flush before reading the monitor log, so
    a single fast packet (one DNS query) is not missed by a read race; (2) a
    clean inspected run (zero captured events) is now reported as "0 outbound
    attempts" instead of being misreported as "monitor output could not be read"
    - the read-failure path is now a distinct `Result.EgressReadFailed` signal.

### Added

- Packet-level egress visibility (the default `meguard run` behavior; see
  Changed above for the default-flip and `--strict`). meguard starts a hardened
  monitor sidecar (its own netns has no route out, only a logging sinkhole) and
  the sandbox joins that netns via `--network container:<monitor>`. Every
  outbound TCP connection attempt (to any IP:port, so hardcoded C2 is caught) and
  DNS query is LOGGED and DROPPED; nothing ever leaves the host. The result
  section lists blocked attempts (e.g. `BLOCKED tcp 185.220.101.5:443`) and
  states an explicit "0 outbound attempts" when the repo made none. A new
  `--monitor-image` overrides the monitor image (default `nicolaka/netshoot`;
  must provide `ip`, `iptables`, `ip6tables`, `tcpdump`+NFLOG). The sandbox
  joining the monitor netns gains NO capability; the monitor is the only
  container granted NET_ADMIN/NET_RAW and runs no repo code. Egress inspection
  rides on an OPTIONAL `EgressInspector` interface, so the core `Runner` is
  unchanged and the `--strict`/`--network none` path never touches the monitor
  code.
  - Fail-closed sealing (hardened after a security review): the monitor sets the
    OUTPUT policy to DROP for IPv4 and IPv6 (interface-independent, so it no
    longer depends on the uplink being named `eth0`), logs via NFLOG in-chain
    before the drop, forces all DNS (incl. Docker's embedded `127.0.0.11`) to the
    sinkhole, runs every critical rule without `|| true`, and verifies the policy
    applied before printing the readiness marker. `waitForMonitorReady` also
    fails fast if the monitor exits before sealing. So a partial or failed seal
    can never reach the sandbox-create step.
  - Marked EXPERIMENTAL and not over-claimed: the pre-run notice, result line,
    and README state the guarantee level and that the in-container mechanics are
    not yet verified on a live Linux Docker host, instead of an unconditional
    "nothing leaves the host".
  - LIVE-VERIFICATION NOTE: the Go orchestration, argv, output, parser, and
    fail-closed ordering are unit tested; the in-container netns/iptables/NFLOG
    behavior still needs one verification pass on a real Linux Docker host (NFLOG
    needs `nfnetlink_log`; tcpdump must support `-i nflog:<group>`).
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
- Egress is always denied. The default `meguard run` inspects (drops + logs)
  egress via a monitor sidecar; `--strict` uses `--network none` (no stack, no
  logs). If the monitor cannot start, the CLI falls back to `--network none`.
- `--memory` and `--cpus` are conservative defaults that will become
  user-configurable.
- scan, analyzers, and tree-sitter are NOT implemented in this slice.
