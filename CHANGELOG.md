# Changelog

All notable changes to meguard are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
meguard stays on 0.x until the CLI surface and any JSON schema stabilize.

## [Unreleased]

### Changed

- `meguard run` and `meguard scan` default output is now COMPACT instead of
  the previous full detail: a one-line header, a per-stage status checklist
  (`sandbox`/`install`/`scan`/`egress`/`secrets` for `run`; `scan` alone for
  `scan`, using `✓`/`!`/`✗` glyphs), a "Top findings" block that lists every
  High/Critical finding individually (capped at 8) with everything else
  rolled into one "... N more" summary line (grouped by analyzer, with a
  "mostly `<dir>`/*" hint when one directory dominates), and a single
  free-text `RESULT: ...` sentence. The raw install log is captured but only
  printed if the install exited non-zero. New `-v`/`--verbose` flag on both
  commands restores the exact previous behavior: the `meguard: preparing
  locked-down sandbox` header with the full active-protections prose, every
  scan finding listed individually with its snippet under `STATIC SCAN`, and
  the streamed `SANDBOX OUTPUT` section. Presentation only: detection,
  containment, exit codes, `--fail-on-scan`, and `--no-scan` behave
  identically in both modes.
- `sandbox.ExecuteOptions` gained a `Diag io.Writer` field
  (`internal/sandbox/execute.go`) for meguard's own operational diagnostics
  (cleanup failures, egress-monitor-read failures), separate from the install
  command's own Stdout/Stderr. Falls back to `Stderr` when unset, so this is
  additive and does not change behavior for any existing caller that has not
  set it.

### Fixed

- Ecosystem detection: a repo that is just a bare Python script with no
  manifest (a top-level `*.py` and nothing else, for example a single
  `apalara.py`) is now detected as python (`python:3.12-slim`) instead of
  falling through to the node defaults and running `npm install` against a
  missing `package.json`. New `hasTopLevelPyFile` fallback in
  `internal/sandbox/detect.go` (`os.ReadDir` of the repo root, still top-level
  and read-only, runs no repo code). There is nothing to install for a
  manifest-less script, so its install command is a NO-OP (`python --version`);
  run the script itself with an explicit `--cmd`. Manifests still win over this
  fallback, and node still wins over python for a polyglot repo.
- `entropy` analyzer: exclude a `.svg` file from the long-line/entropy
  heuristic (`isSVGPath` in `internal/analyze/walk.go`, alongside the
  existing `isMinifiedOrVendorPath`), but ONLY when it carries no `<script>`
  tag (`svgScriptTagRe` in `internal/analyze/entropy.go`), fixing a false
  positive on legitimate SVG icons where `<path d="...">`/`viewBox`
  coordinate data reads as one long, moderately-high-entropy line without
  being an obfuscated payload. An SVG that does carry a `<script>` tag is
  executable, not static graphics, so it loses the exclusion for the whole
  file. Either way the exclusion is entropy-only: `.svg` is deliberately NOT
  added to `proseExtensions`, so `regex.go`'s signature checks (script tags,
  eval, obfuscator fingerprints, exfil URLs, etc.) still scan ALL `.svg`
  content unfiltered and at full severity regardless, since SVG can also
  execute via `onload=`/`onclick=` handlers. New tests:
  `TestEntropyAnalyzerExcludesSVGPathData`,
  `TestEntropyAnalyzerScansSVGWithScriptTag`.

### Added

- Static scan, implemented (`internal/analyze`): manifest, entropy, and regex
  analyzers behind a single `Analyzer` interface, composed by `Scan(repoDir)`,
  which walks the repo once, runs every analyzer, then a correlation pass,
  dedupe, and a deterministic sort. The AST (tree-sitter) analyzer stays a
  labeled no-op behind a cgo build tag on both build variants (real grammar
  wiring is future work); `Report.ASTEnabled`/`ASTDisabledReason` state the
  absence explicitly, so a clean scan is never presented as "AST found
  nothing".
  - `manifest.go`: flags package.json lifecycle scripts (preinstall/install/
    postinstall/prepare/preprepare) with the same pattern set as source files;
    Python manifests (setup.py/pyproject.toml/setup.cfg/Pipfile) are flagged
    at Info.
  - `entropy.go`: per-line length plus Shannon entropy on lines over 300
    characters, catching an obfuscated payload appended after legitimate code
    on the same physical line, in any text file. Excludes `dist/`, `build/`,
    `*.min.js`, `*.bundle.js`.
  - `regex.go`: pattern matching for obfuscation (packer signature,
    Function-constructor eval, global-stashed require, the `_0xNNNN`
    obfuscator fingerprint), download-and-execute, exfiltration channels
    (Discord webhooks, Telegram bot API, raw-paste hosts), credential/wallet
    paths, persistence, recon, bulk `process.env` dumps, plus co-occurrence
    checks for plain-text exfiltration.
  - False-positive controls: severity capped at Info for prose files
    (`.md`/`.mdx`/`.txt`/`.rst`/`.adoc`); a correlation pass escalates two or
    more distinct weak-signal categories co-located in one file into an
    additional High finding; dedupe collapses repeated matches in one file
    into a single finding with an occurrence count.
- `meguard scan <repo-url-or-path>`: a new subcommand that resolves the repo
  the same safe way `run` does (git clone only, no execution) and runs the
  static analyzers alone, with no container and no Docker dependency at all.
  Prints a STATIC SCAN section and exits non-zero if any High/Critical
  finding is reported, so it can gate a CI pipeline on its own.
- `meguard run` now also runs the static scan on the host before creating the
  sandbox, printing the same STATIC SCAN section between the pre-run notice
  and the SANDBOX OUTPUT section. Findings are ADVISORY by default: the
  sandboxed run proceeds regardless of what scan found, because containment,
  not scan, is the safety net. Two new flags:
  - `--no-scan`: skip the static scan entirely, restoring the pre-scan
    behavior exactly.
  - `--fail-on-scan`: after the sandboxed run completes, exit non-zero if the
    static scan reported any High or Critical finding.
  A scan failure (for example an unreadable repo dir) is logged to stderr and
  never blocks the sandboxed run.
- `internal/sandbox` still never imports `analyze` (unchanged;
  `TestSandboxDoesNotImportAnalyze` still passes). `cmd` (where `run` and
  `scan` live) now legitimately does import `analyze`, a deliberate,
  reviewed architecture point: detection and containment are combined at the
  CLI layer, while the sandbox's containment guarantee stays structurally
  independent of scan.

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

- CI workflow (`.github/workflows/ci.yml`): runs on every push and pull request
  against `main`. Checks out, sets up Go from `go.mod`, then runs `gofmt -l`,
  `go mod verify`, `go build ./...`, `go vet ./...`, `go test ./...`, and a
  dedicated step that rebuilds the pure static binary (`CGO_ENABLED=0`) and
  confirms `go version -m` reports `CGO_ENABLED=0`, enforcing the "run binary
  stays pure Go" rule from CLAUDE.md in CI, not just at release time.
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
  - Not over-claimed: the pre-run notice, result line, and README state the
    guarantee level rather than an unconditional "nothing leaves the host". Live
    verification on Docker/OrbStack is recorded under Changed above.
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
- Egress is always denied. The default `meguard run` inspects (drops + logs)
  egress via a monitor sidecar; `--strict` uses `--network none` (no stack, no
  logs). If the monitor cannot start, the CLI falls back to `--network none`.
- `--memory` and `--cpus` are conservative defaults that will become
  user-configurable.
- scan (manifest, entropy, regex analyzers) is implemented; see the Added
  entry near the top of this file. The AST/tree-sitter analyzer is still NOT
  implemented, a labeled no-op on both build variants.
