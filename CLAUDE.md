# CLAUDE.md - meguard working contract

meguard is a fast, lightweight Go CLI that safely executes untrusted repositories
(for example fake-interview repos that hide infostealer or RAT payloads) inside a
locked-down container sandbox, and statically scans them for signs of hidden
malicious code. It optimizes for fast startup, a single static binary, and
small memory. The pure static build stays cgo-free (see "Scan architecture"
below for the one cgo-gated exception, the AST analyzer).

This file is the working contract. Read it before making changes.

## The five safety invariants (never violate; the tool exists for these)

1. meguard NEVER executes repo code on the host. `git clone` only (cloning does
   not run install hooks). All execution happens inside the container.
2. NO host bind mounts of the repo or $HOME. Copy the repo INTO a container
   tmpfs via `docker cp`. The container must have no route to host secrets.
3. Sandbox defaults are locked down; configuration only ever RELAXES. A
   zero-value Profile must be the safest Profile. A forgotten field cannot open
   a hole.
4. Network egress is ALWAYS denied - no repo traffic ever reaches the network.
   Two modes deny it, and configuration only ever chooses between them:
   - DEFAULT (CLI): INSPECTED mode. The sandbox joins a monitor sidecar's netns
     that is sealed fail-closed (OUTPUT DROP policy for IPv4+IPv6, verified
     before the sandbox is created); every outbound attempt is logged then
     dropped. Egress is denied by policy.
   - `--strict`: `--network none`, no network stack at all. Egress is denied by
     absence. This is the strongest, fully verified mode.
   Neither mode ever permits egress. The library-level default (the zero-value
   Profile) is still `--network none`; INSPECTED is a CLI default only. If the
   monitor cannot start, the CLI falls back to `--network none` (never to open
   egress). Inspected mode is EXPERIMENTAL until verified on a live Linux host.
5. Cleanup (`docker rm -f`) MUST run on install failure, panic, or Ctrl-C, for
   BOTH the sandbox and (in inspected mode) the monitor. Use defer plus signal
   handling.

Where they live in code:
- Invariant 1: `cmd/run.go` `resolveRepo` (git clone only on host) and
  `internal/sandbox` (all exec via `docker exec`).
- Invariant 2: `internal/sandbox/args.go` (tmpfs mounts, no bind mounts) and
  `docker.go` `CopyInto` (`docker cp`).
- Invariant 3: `internal/sandbox/profile.go` (zero value is safest - including
  InspectEgress=false -> `--network none`; Normalize only fills gaps) and
  `args.go` (hardening flags are unconditional). NOTE: the CLI defaults egress
  inspection ON (a deliberate product choice); the Profile zero value stays
  `--network none`, so a forgotten field still cannot open a hole.
- Invariant 4: `internal/sandbox/args.go` `networkArgs` (`--network none` vs
  join the monitor netns) and `egress.go` `monitorScript` (fail-closed seal).
- Invariant 5: `internal/sandbox/execute.go` (deferred detached-context Remove
  for both containers) and `main.go` (signal.NotifyContext).

Scan lives in `internal/analyze` (analyzers) and `cmd/run.go`/`cmd/scan.go`
(CLI wiring); see "Scan architecture" below. It is a read-only, host-side,
advisory detector layered on top of the five invariants above, not a
replacement for any of them.

## Container lifecycle (implemented exactly this)

    docker create <hardened args> <image> sleep infinity
    docker start <id>
    docker exec -i <id> tar -xf - -C /repo   (repo streamed in; see note below)
    docker exec <id> <install cmd>           (capture and stream stdout/stderr)
    docker rm -f <id>                        (always)

IMPLEMENTATION NOTE on invariant 2 (kept verbatim above): the mechanism is a
tar stream through `docker exec`, NOT literal `docker cp`. End-to-end testing
showed Docker refuses `docker cp` into a --read-only container (the read-only
rootfs guard blocks it even for a tmpfs target). meguard builds a deterministic
tar in-process (internal/sandbox/copy.go) and pipes it to a `tar` process inside
the running container, which writes to the /repo tmpfs and is not subject to the
read-only guard. This preserves the invariant's security property exactly: no
host bind mounts, repo lives in a container tmpfs, no route to host secrets.
Because the copy runs inside the container, the container is STARTED before the
copy (lifecycle order: create, start, copy, exec). The image must provide `tar`
(standard in Debian and Alpine bases).

Required hardening flags on create (see `internal/sandbox/args.go`):

    --user 1000:1000
    --cap-drop ALL
    --security-opt no-new-privileges
    --read-only
    --tmpfs /repo:exec,mode=1777  --tmpfs /home/sandbox  --tmpfs /tmp
    --pids-limit 512
    --memory 2g  --cpus 2
    --network none            (conditional: default INSPECTED mode instead joins
                               the monitor netns via --network container:<mon>;
                               --strict forces --network none. See invariant 4.)
    -w /repo
    -e HOME=/home/sandbox

Only two ecosystem-specific values are configurable: `--image` (default
node:20-slim) and `--cmd` (default `npm install`). When they are unset they are
auto-detected from the repo's manifests by `sandbox.DetectEcosystem` (node and
python; see `internal/sandbox/detect.go`); an explicit flag always wins and an
unrecognized repo falls back to the node defaults. Detection reads only file
existence (no repo code runs; invariant 1) and only ever supplies these two
RELAX values, never a security control (invariant 3). `--memory` and `--cpus`
are conservative defaults that will become user-configurable; a large install
may need more than 2g.

## Runtime requirement

meguard shells to the `docker` CLI via os/exec. This requires a
Docker-COMPATIBLE runtime on PATH, NOT Docker Desktop specifically. Any of these
satisfy it with no code change: Docker, OrbStack (macOS, light), Colima
(macOS/Linux, light), Podman (daemonless, rootless). Never tell users Docker
Desktop is the only option.

The container daemon is a TRUST BOUNDARY. Documented upgrade paths (see
`internal/sandbox/runner.go`):
- Docker Go SDK, if CLI output parsing gets fragile.
- Future Runner backends, in preference order for a security tool: Podman
  rootless (removes the root-daemon trust boundary), then gVisor (runsc), then
  Firecracker microVMs (strongest kernel boundary).

## Scan architecture (implemented; see `internal/analyze`)

meguard is a container AND a detector: `meguard run` combines the sandbox with
a static scan (advisory by default), and `meguard scan` runs the same
detection alone, with no container and no Docker dependency at all.

- Built from analyzers behind a single `Analyzer` interface
  (`internal/analyze/analyze.go`): `Name() string` and
  `Analyze(files []ScannedFile) ([]Finding, error)`. `Scan(repoDir string)`
  walks the repo ONCE (`internal/analyze/walk.go`, `walkFiles`), then runs
  every analyzer against the shared result, then a correlation pass, dedupe,
  and sort.
- Pure-Go analyzers (CGO_ENABLED=0), all read-only:
  - `manifest.go`: package.json lifecycle scripts (preinstall/install/
    postinstall/prepare/preprepare), scanned with the same risky-pattern set
    as source files; Python manifests (setup.py/pyproject.toml/setup.cfg/
    Pipfile) flagged at Info (arbitrary code can run at install time,
    inherent to the ecosystem).
  - `entropy.go`: per-line length + Shannon entropy on lines over 300 chars.
    This is the generalized version of "a huge obfuscated payload appended
    after legitimate code on the same physical line" (see decision log): it
    catches that shape in ANY text file, without hardcoding a filename.
    Excludes `dist/`, `build/`, `*.min.js`, `*.bundle.js` paths (checked-in
    minified bundles are normal on their own).
  - `regex.go`: cheap first-pass pattern matching across several categories -
    obfuscation (packer signature, `Function`-constructor eval, `global`/
    `globalThis` require-stashing, `_0xNNNN` obfuscator-tool fingerprint),
    download-and-execute (curl/wget-pipe-to-shell, Python shell exec, Windows
    LOLBins scoped to `.ps1`/`.bat`/`.cmd`/`.vbs`), exfiltration channels
    (Discord webhooks, Telegram bot API, raw-paste hosts), credential/wallet
    file paths, persistence mechanisms, recon/fingerprinting, and bulk
    `process.env` dumps. Two co-occurrence checks cover PLAIN-TEXT
    exfiltration (not just obfuscated payloads): a network call plus a
    secrets marker anywhere in one file, and a network call inside a
    build/lint/tooling config file that has no legitimate reason to make one.
- The AST analyzer (tree-sitter) needs cgo, isolated behind build tags so it
  is the sole cgo dependency and degrades to a labeled no-op when compiled
  out (`internal/analyze/ast.go`, `ast_cgo.go`, `ast_nocgo.go`):

      //go:build cgo      -> astDisabledReason: "not yet implemented for this build (grammar not wired)"
      //go:build !cgo     -> astDisabledReason: "needs a cgo build"

  Both variants currently return a `noopAnalyzer`: wiring a real tree-sitter
  grammar is future work, out of scope for this slice. `Report.ASTEnabled` is
  always false today; `Report.ASTDisabledReason` is always set when it is
  false, so the absence is stated, never silent. A clean scan on the pure
  build is NEVER presented as "AST found nothing".
- False-positive controls (first-class, not an afterthought):
  - Severity is capped by whether a file can actually execute: prose
    (`.md`/`.mdx`/`.txt`/`.rst`/`.adoc`) is capped at Info, since a string
    appearing in documentation is evidence of nothing (this repo's own
    CLAUDE.md and docs/decisions.md discuss an example payload as prose, and
    scan must not treat its own docs as a threat).
  - A correlation pass (`correlate` in `analyze.go`) escalates two or more
    distinct WEAK categories co-located in one file (e.g. a credential-path
    marker plus recon) into one additional High finding, so individually
    common signals only matter combined.
  - Dedupe collapses repeats of the same (analyzer, category, message, file)
    into one finding with an occurrence count, so one large or repetitive
    file cannot flood the report.
  - The entropy analyzer excludes `.svg` (`isSVGPath` in `walk.go`, alongside
    `isMinifiedOrVendorPath`), but ONLY when the file has no `<script>` tag
    (`svgScriptTagRe` in `entropy.go`): SVG path/viewBox attributes are
    legitimately one long line of numeric coordinate data, which reads as
    long and moderately high-entropy without being an obfuscated payload, but
    an SVG that carries a `<script>` tag is executable, not static vector
    graphics, and loses the exclusion (the whole file, since a
    script-carrying SVG is unusual enough on its own to warrant scrutinizing
    its other long lines too). This exclusion is entropy-only regardless: it
    does NOT treat SVG as inert. `.svg` is deliberately absent from
    `proseExtensions` (SVG can also execute via `onload=`/`onclick=`
    handlers, not just `<script>`, a real XSS vector), so regex.go's
    signature checks keep scanning ALL `.svg` content unfiltered and at full
    severity regardless of this exclusion.
- Two build variants ship: pure static (no AST) and cgo (full). Same binary
  name and commands.
- `internal/sandbox` NEVER imports `analyze` or any analyzer; purity there is
  structural, enforced by `TestSandboxDoesNotImportAnalyze` in
  `internal/sandbox/import_guard_test.go`. `cmd` (the CLI layer "run" and
  "scan" live in) DOES import `analyze`, by design: that is how detection and
  containment are combined in one command. What must stay independent is the
  sandbox's containment guarantee (a bug in scan must never be able to weaken
  it), not the CLI layer above it.
- `cmd/run.go` calls `analyze.Scan` on the resolved repo dir on the HOST,
  read-only, before any container work (same trust tier as
  `sandbox.DetectEcosystem`). Findings are ADVISORY: the sandboxed run
  proceeds regardless of what scan found (containment, not scan, is the
  safety net) unless `--fail-on-scan` is set, which exits non-zero after the
  run completes if any High/Critical finding was reported. `--no-scan` skips
  scanning entirely. `meguard scan <repo>` runs the same detection alone, with
  no Docker dependency, and exits non-zero on any High/Critical finding by
  default (its whole purpose is triage/gating).
- Output verbosity: both commands default to a COMPACT report (a one-line-
  per-stage status checklist, only the High/Critical findings individually
  with the rest rolled into one summary line, and no raw install log unless
  the install failed) so the default run is legible to a human at a glance.
  `-v`/`--verbose` restores the full report: the protections rationale, every
  finding, and the streamed install log. Nothing about detection or
  containment changes between the two; this is presentation only (see
  `printCompactReport`/`printCompactScanSection` in `cmd/run.go`/`cmd/scan.go`
  vs. `printPreRunNotice`/`printScanSection`/`printResult`).
  `cmd/run.go` buffers the install command's own Stdout/Stderr into a
  discardable buffer to implement this (only flushed on a non-zero exit or a
  hard error), but `sandbox.ExecuteOptions` has a separate `Diag` writer
  (`internal/sandbox/execute.go`) for meguard's OWN operational diagnostics
  (cleanup failures, egress-monitor-read failures), which `cmd/run.go` always
  points at the real stderr regardless of `-v` or exit code. This split
  exists so a `docker rm -f` or monitor-read failure is never silently lost
  inside the discarded buffer just because the install itself succeeded
  (found by the security-reviewer gate on this change; see decision 0017).

## Build and test commands (both variants)

    # Pure static build (no AST; run binary is cgo-free)
    CGO_ENABLED=0 go build -o meguard .

    # Full cgo build (adds AST analyzer once scan exists)
    CGO_ENABLED=1 go build -tags cgo -o meguard .

    # Standard checks
    go build ./...
    go vet ./...
    go test ./...

    # Prove the run binary is cgo-free
    go version -m meguard | grep CGO_ENABLED   # expect CGO_ENABLED=0 on pure build

Guard tests:
- `TestCreateArgsHardening` (argv contract): FAILS if any hardening flag is
  removed from or altered in `createArgs`.
- `TestSandboxDoesNotImportAnalyze` (architecture): PASSES now; FAILS if
  `internal/sandbox` gains any transitive dependency on analyze or an analyzer.

## Coding standards

- Idiomatic Go. Keep it small and readable.
- `context.Context` on anything that shells out; use `exec.CommandContext`.
- Wrap errors with `%w`.
- Table-driven tests.
- No naked panics in library code; return errors.
- No em dashes in comments or output. Use plain ASCII punctuation.
- The `run` binary and `internal/sandbox` stay pure Go. Never add a cgo
  dependency to that path.

## Subagent roster (see .claude/agents/)

- `security-reviewer`: adversarial. Audits create-argv and Profile against the
  five invariants; confirms no host execution, no host mounts, egress denied;
  traces a stage-2 payload through the code. Run as the gate before calling any
  change done.
- `docs-scribe`: owns README.md, docs/documentation.md, docs/launch.md,
  CHANGELOG.md, docs/decisions.md. Run after any code change to resync all of
  them.
- `test-engineer`: writes the argv contract test, the sandbox-import guard test,
  and table-driven tests.

## STANDING RULES (do these in the SAME change as any code change)

In the same change as any code change, the contributor updates:
- README.md
- docs/documentation.md
- CHANGELOG.md (append under [Unreleased])
- docs/decisions.md, when a decision is made or reversed
- docs/launch.md, whenever build or release steps change

No code change lands with these out of sync.
