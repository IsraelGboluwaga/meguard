# Decision log

Lightweight ADR-style log. Each entry records the decision, the alternatives
considered, and a one-line reason. Every future decision or reversal is appended
here.

## 0001 - Language: Go over Rust or TypeScript

- Decision: Build meguard in Go.
- Alternatives: Rust; TypeScript/Node.
- Reason: Fast startup, a single static binary, and small memory, with a simple
  cgo-free build for the security-critical path; simpler than Rust for this shape
  of tool and lighter than a Node runtime.

## 0002 - Run-led, not scan-led

- Decision: Ship the `run` sandbox first; document scan but do not implement it.
- Alternatives: Build scan (static analysis) first; build both at once.
- Reason: The containment guarantee is the core value and is independent of scan;
  scan can be added later behind a clean interface without touching run.

## 0003 - Copy repo into tmpfs, not bind-mount

- Decision: `docker cp` the repo into a container tmpfs.
- Alternatives: Bind-mount the repo (and/or $HOME) from the host.
- Reason: A bind mount gives repo code a path to host files; copying into an
  ephemeral tmpfs leaves no host route to secrets.

## 0004 - Zero-value-locked-down Profile

- Decision: All security controls are hardcoded in the create argv; `Profile`
  holds only non-security choices, and its zero value is the safest.
- Alternatives: Make hardening configurable via Profile fields with safe
  defaults.
- Reason: A forgotten or zero-valued field must never open a hole; keeping
  controls out of configuration makes safety structural.

## 0005 - Docker CLI over Docker SDK

- Decision: Shell out to the `docker` CLI via os/exec behind a `Runner`
  interface.
- Alternatives: Use the Docker Go SDK now.
- Reason: The CLI keeps the binary tiny and dependency-light and works across
  Docker/OrbStack/Colima/Podman unchanged; the SDK is the documented upgrade path
  if output parsing gets fragile.

## 0006 - Build tags on the AST analyzer only

- Decision: Isolate the tree-sitter AST analyzer behind cgo build tags so it is
  the sole cgo dependency, degrading to a labeled no-op when compiled out.
- Alternatives: Make the whole binary cgo; use a pure-Go parser; drop AST.
- Reason: Keeps the default path cgo-free and portable while still allowing a
  full AST-capable build; the pure build states the AST absence rather than
  hiding it.

## 0007 - Two build variants (pure + cgo)

- Decision: Ship a pure static variant (no AST) and a full cgo variant, same
  binary name and commands.
- Alternatives: Ship only one variant.
- Reason: Serves both zero-dependency portability and full-analysis power without
  splitting the CLI surface.

## 0008 - Container daemon treated as a trust boundary; backend roadmap

- Decision: Document the container daemon as a trust boundary and record the
  backend preference order for a security tool: Podman rootless, then gVisor,
  then Firecracker.
- Alternatives: Treat the daemon as fully trusted; commit to a single backend.
- Reason: Being explicit about the trust boundary sets the direction toward
  stronger isolation without blocking the initial Docker-CLI implementation.

## 0009 - Preflight the runtime before doing any work

- Decision: `run` runs `docker info` first and fails fast with runtime-agnostic
  guidance if no runtime is reachable, before cloning or printing the notice.
- Alternatives: Let `docker create` fail and surface its raw error; skip any
  check.
- Reason: A clear, actionable message (naming OrbStack/Colima/Podman, not just
  Docker Desktop) is better UX than a raw daemon error printed after a misleading
  pre-run notice.

## 0010 - Copy the repo via a tar stream through docker exec, not docker cp

- Decision: Stream a Go-built tar into a `tar` process inside the running
  container (`docker exec -i ... tar -xf - -C /repo`) instead of `docker cp`, and
  start the container before copying. Mount /repo tmpfs `mode=1777`.
- Alternatives: Use `docker cp` (fails: Docker refuses it into a --read-only
  container, confirmed in end-to-end testing); drop `--read-only` so `docker cp`
  works (rejected: --read-only is required hardening).
- Reason: Keeping `--read-only` is non-negotiable for a security tool, so the
  copy must not depend on it being off. The tar-through-exec path preserves
  invariant 2 exactly (no bind mount, repo in tmpfs) and, building the tar
  in-process, avoids host `tar` quirks (AppleDouble files, xattr warnings,
  mount-point metadata errors). Cost: the image must contain `tar` (standard in
  Debian and Alpine bases).

## 0011 - Distribute via goreleaser + a Homebrew tap; pure build first

- Decision: Ship releases with goreleaser and GitHub Actions, publishing a
  Homebrew formula to a `homebrew-tap` repo. Release the pure static
  (CGO_ENABLED=0) binary now; add the cgo/full variant when scan exists.
- Alternatives: apt/PPA (rejected: needs hosted Debian repo infrastructure, too
  heavy for 0.x); ship both variants immediately (rejected: no cgo code exists
  yet, so a cgo build is identical to the pure build today).
- Reason: Homebrew is the lowest-friction path for a Go CLI and works on macOS
  and Linux; goreleaser makes the formula, checksums, and cross-builds
  reproducible from a single tag. Deferring the cgo variant avoids per-platform C
  toolchain complexity in CI until it actually buys something.

## 0012 - Expose the runtime as a user flag; prefer rootless for hostile code

- Decision: Add `--runtime` to `meguard run`, wiring straight to
  `DockerRunner.Binary` (default `docker`), and steer users toward a rootless
  runtime (`--runtime podman`) for genuinely hostile code. Surface the chosen
  runtime in the pre-run notice, labeled the trust boundary.
- Alternatives: Keep `DockerRunner.Binary` unexposed and hardcode `docker`
  (rejected: the runtime is the single largest residual risk per decision 0008,
  yet was unreachable from the CLI, so users could not pick the safer backend);
  default to `podman` (rejected: docker is the most commonly installed runtime,
  and a wrong default fails preflight for most users).
- Reason: Per decision 0008 the daemon is the trust boundary and rootless
  Podman removes the root-daemon boundary. Making that choice a first-class,
  documented flag turns the biggest available blast-radius reduction from a
  code-only struct field into something a user can actually select, without
  changing any hardening default.

## 0013 - Terminate git clone options with `--`

- Decision: Clone with `git clone --depth 1 -- <source> <dir>`.
- Alternatives: Rely on the `isGitURL` prefix gate alone (rejected: correct
  today, but a single point of failure on the one host command that parses an
  attacker-controlled string; a future change to the gate could silently
  reintroduce option injection).
- Reason: `--` makes it structurally impossible for a source beginning with `-`
  to be parsed as a git flag (for example `--upload-pack`), independent of the
  gate. Cheap, unconditional defense in depth on the host-side boundary.

## 0014 - Egress visibility via a packet-level monitor sidecar, not a proxy

- Decision: Add opt-in `--inspect-egress`. When set, a hardened monitor sidecar
  seals its own network namespace (real uplink torn down, default route pointed
  at a dummy sinkhole, `iptables` DROP + DNS redirect) and captures every
  outbound SYN and DNS query with `tcpdump`; the sandbox joins that netns via
  `--network container:<monitor>`. Blocked attempts are reported per line. The
  default stays `--network none`. The monitor is the only container granted
  NET_ADMIN/NET_RAW and runs NO repo code; the sandbox keeps `--cap-drop ALL`.
  meguard waits for the monitor's readiness marker before creating the sandbox,
  so the sandbox never joins an unsealed netns (fail closed).
- Alternatives:
  - A logging HTTP/S proxy (rejected: only sees proxy-aware HTTP(S); raw-socket
    malware bypasses it silently, giving dangerous false confidence in a
    security tool).
  - A DNS sinkhole only (rejected: misses connections to hardcoded IPs, exactly
    the evasion C2/miners use; packet-level SYN capture subsumes it).
  - Keeping `--network none` and never reporting (rejected: the product promise
    is "run it to SEE it is safe", and silent containment delivered only half of
    that; this was the standing TODO).
- Reason: A security tool must not under-report. Packet-level capture sees every
  connection attempt to any IP:port plus DNS, so a hardcoded-IP beacon is logged,
  not missed. It relaxes invariant 4 in wording only: egress is still fully
  denied (the netns has no route out); the relaxation just makes the denial
  observable, and it is opt-in so the zero-value posture is unchanged
  (invariant 3). LIVE-VERIFICATION NOTE: the in-container netns/iptables script
  needs one verification pass on a Linux Docker host; the Go layers are unit
  tested.
- Update (post security-review gate): the first cut sealed egress with an
  interface-specific `iptables -A OUTPUT -o eth0 -j DROP` guarded by `|| true`,
  handled no IPv6, and printed the readiness marker regardless of whether the
  rule applied - a fail-OPEN gap. Hardened to fail-CLOSED: the seal is now an
  OUTPUT DROP policy (interface-independent) for IPv4 and IPv6, DNS is forced to
  the sinkhole, capture moved to NFLOG in-chain (before the drop), every critical
  rule runs without `|| true`, and the script verifies the policy before echoing
  readiness; `waitForMonitorReady` fails fast if the monitor exits first. The
  feature is labeled experimental and its user-facing text no longer claims
  unconditional containment until the live-verification pass lands.
- Update (default flip, at the maintainer's direction): egress inspection is now
  the DEFAULT for `meguard run`; the old opt-in `--inspect-egress` flag is
  removed and `--strict` is the opt-out to `--network none`. Rationale: the
  product promise is "run it to SEE what it tried", so visibility should be the
  default experience, not an opt-in. Safety is preserved three ways: (1) egress
  is denied in BOTH modes; (2) the library zero-value Profile is still
  `--network none`, so invariant 3 (a forgotten field cannot open a hole) is
  unchanged - the flip is a CLI default only; (3) because inspected mode is
  experimental and needs a monitor image + NFLOG, a monitor that cannot start
  makes the CLI fall back to `--network none` with a warning
  (`ErrMonitorUnavailable`), never to open egress and never silently. CLAUDE.md
  invariant 4 is rewritten from "hardcoded `--network none`" to "egress always
  denied, in one of two modes".
- Update (live-verified): the seal was verified on Docker/OrbStack (a real Linux
  kernel) - hardcoded-IP SYNs logged+dropped, no leak to a sibling container on
  the bridge subnet (proving the OUTPUT DROP policy seals on-link routes), DNS
  captured by name, IPv6 sealed, clean run reports zero attempts, fallback works,
  no container leaks. Two bugs found and fixed during verification: a read race
  (fixed with a ~1.2s flush wait before reading the monitor log) and a
  nil-vs-empty misreport of a clean run as "could not be read" (fixed with a
  distinct `Result.EgressReadFailed`). Not yet checked: rootless runtimes
  (Podman) and kernels without `nfnetlink_log`, where the monitor fails to start
  and the CLI falls back to `--network none`.

## 0015 - Ecosystem auto-detection from repo manifests

- Decision: When `--image` / `--cmd` are unset, detect the ecosystem by reading
  the repo's top-level manifest files (`sandbox.DetectEcosystem`) and supply the
  image + install command. Ordered detectors, first match wins: node before
  python; within python, `requirements.txt` before a project manifest. Node and
  python are the only ecosystems detected for now. No match falls back to the
  locked-down defaults; an explicit flag always overrides. Reverses the earlier
  "auto-detection is out of scope (tier-2)" note.
- Alternatives: Keep requiring `--image`/`--cmd` (rejected: needless friction
  for the two common cases meguard targets); read manifest CONTENTS to pick
  package managers (yarn/pnpm/poetry) precisely (deferred: node:20-slim ships
  only npm and reading contents is more surface than existence checks buy today);
  put detection in a future `analyze` package (rejected: it selects a sandbox
  RELAX value and must not pull `analyze` into the sandbox path, per the import
  guard).
- Reason: Choosing an image is not executing code, so detection stays on the safe
  side of invariant 1 by only calling `os.Stat`; it only ever fills the two RELAX
  values, never a security control, so invariant 3 holds. The node case reuses
  `DefaultImage`/`DefaultInstallCmd` to avoid drift, and pip uses `--user` so
  installs land on the writable HOME tmpfs under the read-only root.
- Refinement (2026-09-08): Added a python fallback for a repo that is just a
  bare `.py` file with no manifest at all (`hasTopLevelPyFile`, an `os.ReadDir`
  of the repo root, still top-level and read-only). Without it such a repo fell
  through both detectors to the node defaults and ran `npm install` against a
  missing `package.json` (observed on `IsraelGboluwaga/apalara`: a single
  `apalara.py`). The fallback lands the sandbox in `python:3.12-slim`. There is
  nothing to install, so the install command is a NO-OP (`python --version`),
  chosen deliberately over auto-running the script: meguard executes the
  ecosystem's install step, but auto-executing an arbitrary untrusted `.py` is a
  choice the user makes explicitly with `--cmd`, so invariant 1's "no repo code
  runs unless the user asked" spirit holds. Manifests still win over the loose
  fallback, and node still wins over python.

## 0016 - Implement scan; `run` becomes "container AND detector"

- Decision: Implement `internal/analyze` for real (manifest, entropy, regex
  analyzers; a labeled-no-op AST seam behind cgo build tags) and wire it into
  `meguard run`, which now statically scans a repo before the sandboxed run
  and prints a STATIC SCAN section. Findings are ADVISORY by default (the
  sandboxed run proceeds regardless; containment, not scan, is the safety
  net) unless `--fail-on-scan` is set. `--no-scan` restores the pre-scan
  behavior exactly. A new `meguard scan <repo>` subcommand runs the same
  detection alone, with no Docker dependency at all, and exits non-zero on
  any High/Critical finding by default. This reverses decision 0002
  ("Run-led, not scan-led": ship run first, document scan, do not implement
  it) now that run is solid (egress inspection, decision 0014, just landed
  and was live-verified).
- Alternatives: Keep scan document-only indefinitely (rejected: the
  motivating case - a build-time RCE hidden as an obfuscated payload
  appended after `} satisfies Config;` on the same physical line of a
  `tailwind.config.ts`, invisible unless you scroll - is exactly what static
  inspection catches and pure containment does not surface); make scan
  findings BLOCK the sandboxed run by default (rejected: the product's core
  value is "run it to SEE what happens", established by decision 0014's
  egress visibility; a heuristic scanner has both false positives and false
  negatives, so making it an involuntary gate would either block legitimate
  repos on a noisy match or give false confidence when it stays quiet -
  advisory-by-default with an explicit `--fail-on-scan` opt-in serves both
  the "always run it" and "gate my CI" cases without changing the default
  behavior anyone already depends on); wire a real tree-sitter AST analyzer
  now (deferred: it is a materially larger dependency and per-language
  grammar surface than manifest/entropy/regex needed to catch the motivating
  case, and CLAUDE.md already anticipated exactly this seam - build-tag
  isolated, labeled no-op when absent - so implementing the seam without the
  grammar keeps the documented architecture live and honest rather than
  half-built).
- Reason: Detection and containment now compose instead of one blocking the
  other. `internal/sandbox` still never imports `analyze` (unchanged,
  `TestSandboxDoesNotImportAnalyze` still passes); `cmd` now legitimately
  does, which is where the two are combined. Every analyzer only reads file
  bytes (`internal/analyze/walk.go`, `os.ReadFile`) on the host, before any
  container work - the same trust tier as `sandbox.DetectEcosystem` - so
  invariant 1 is unaffected. False-positive control was designed in
  alongside detection, not bolted on after: severity is capped by whether a
  file can actually execute (prose is capped at Info - this repo's own
  CLAUDE.md and docs/decisions.md discuss an example payload as prose, and
  scan must not treat its own docs as a threat), a correlation pass only
  escalates when two or more DISTINCT weak signal categories land in the
  same file, and dedupe collapses repeated matches so one large file cannot
  flood the report.

## 0017 - Compact-by-default CLI output; `-v`/`--verbose` for full detail

- Decision: `meguard run` and `meguard scan` default to a COMPACT report: a
  one-line header, a per-stage status checklist (`✓`/`!`/`✗` glyphs), a "Top
  findings" block listing every High/Critical finding individually (capped
  at 8, `maxTopFindings`) with everything else rolled into one "... N more"
  line (grouped by analyzer, plus a "mostly `<dir>`/*" hint when one
  directory dominates), and a single free-text `RESULT: ...` sentence. The
  raw install log is captured but only printed if the install exited
  non-zero. New `-v`/`--verbose` flag restores the exact previous output:
  the `meguard: preparing locked-down sandbox` header with the full
  active-protections prose, every finding listed individually with its
  snippet, and the streamed install log.
- Alternatives: keep the full report as the only output (rejected: a user
  found it too verbose to read at a glance once a repo had several findings
  and a long install log - not scannable by eye); make compact the only mode
  with no way back to full detail (rejected: full detail is still needed to
  debug a failed install or audit every finding, not just the High/Critical
  ones). A few compact mockup shapes were tried before landing on the
  status-checklist-plus-top-findings layout (a single summary line lost too
  much; a table felt heavier than plain lines) as the most legible at a
  glance.
- Reason: Presentation only. Detection, containment, exit codes,
  `--fail-on-scan`, and `--no-scan` behave identically in both modes; only
  what gets printed changes. Keeping the exact old report behind `-v`
  preserves it for anyone already relying on it (scripts scraping output,
  existing habits) while making the default legible.
- Follow-up correctness fix (found by the security-reviewer gate on this
  change, before it landed): the compact implementation initially buffered
  the install command's Stdout AND Stderr into one discardable
  `bytes.Buffer`, only flushed on a non-zero exit or a hard error. But
  `sandbox.Execute` also writes its OWN operational diagnostics (a `docker rm
  -f` cleanup failure, an egress-monitor-read failure) to that same Stderr,
  so on a successful install those diagnostics were silently discarded too -
  exactly the case `printCompactEgressLine`'s "see stderr" message for a
  monitor-read failure depends on. Fixed by adding a separate `Diag
  io.Writer` field to `sandbox.ExecuteOptions` (falls back to `Stderr` when
  unset, so this is additive) for meguard's own diagnostics only;
  `cmd/run.go` always points `Diag` at the real stderr regardless of `-v` or
  exit code, so only the install command's own stdio is ever buffered away.
  New tests: `TestExecuteCleanupFailureGoesToDiagNotStderr`,
  `TestExecuteMonitorReadFailureGoesToDiagNotStderr`,
  `TestExecuteDiagFallsBackToStderrWhenUnset`.

## 0018 - Entropy-only SVG exclusion, conditional on no `<script>` tag

- Decision: exclude a `.svg` file from `entropy.go`'s long-line heuristic
  only when it carries no `<script>` tag (`isSVGPath` in `walk.go` plus
  `svgScriptTagRe` in `entropy.go`, alongside the existing
  `isMinifiedOrVendorPath`). A script-carrying SVG loses the exclusion for
  the whole file. `.svg` is deliberately NOT added to `proseExtensions`
  either way, so `regex.go`'s signature checks (script tags, eval,
  obfuscator fingerprints, exfil URLs, etc.) keep scanning ALL `.svg`
  content unfiltered and at full severity regardless of this exclusion.
- Alternatives: treat `.svg` as prose/inert like `.md` by adding it to
  `proseExtensions` (rejected: SVG can execute via inline `<script>` and
  `onload=`/`onclick=` handlers, a real XSS vector, so capping severity
  across the board would hide a genuine threat class); exclude `.svg`
  unconditionally by extension alone, with no content check (the first cut
  of this fix; superseded by this decision after review pointed out it
  would blind the entropy heuristic to a long, high-entropy payload
  deliberately hidden inside an SVG's own `<script>` tag - a real gap, even
  though `regex.go`'s signature checks would likely still catch a KNOWN
  pattern in that script); leave `.svg` unexcluded everywhere (rejected: it
  was one of the noisiest false positives found - a legitimate
  `public/placeholder.svg`'s `path d="..."`/`viewBox` coordinate data was
  flagged High, since it is naturally one long line that reads as
  moderately-high-entropy without being an obfuscated payload).
- Reason: the entropy heuristic's failure mode (long line, moderate entropy)
  is specific to inert SVG coordinate data, not to SVG as a format, so the
  fix is scoped exactly to that case. Gating on `<script>` presence keeps
  the false-positive fix for ordinary icons while not creating a new blind
  spot for the exact executable case the format is risky for; a
  script-carrying SVG is also unusual enough on its own that scrutinizing
  its other long lines too, not just the script, is the conservative
  choice. New tests: `TestEntropyAnalyzerExcludesSVGPathData`,
  `TestEntropyAnalyzerScansSVGWithScriptTag`.

## 0019 - Progress spinner on stderr; drop the compact command echo

- Decision: on the compact (non--verbose) path, animate a single in-place
  spinner line on stderr while the slow, otherwise-silent stages run (the
  static scan, and, for `run`, the in-container install), and remove the
  redundant `meguard run <source>` header line (compact `scan`'s header is
  reduced to the fixed `meguard scan (no container; read-only)` mode line,
  dropping the repeated source path). The spinner lives in `cmd/spinner.go`
  and is a no-op when stderr is not a terminal.
- Alternatives: a full progress bar or per-stage timing (rejected: the stages
  are coarse and their durations unknown up front - a spinner conveys
  "working" without implying a measurable percentage); print static "scanning
  ..."/"installing ..." lines with no animation (rejected: on a multi-second
  install with no output they still read as frozen; an animation is the signal
  that the process is alive); write the spinner to stdout (rejected: stdout
  carries the machine-relevant report, and a spinner's carriage returns would
  corrupt it when piped - stderr is the correct channel for progress chrome);
  add `golang.org/x/term` for terminal detection (rejected: the run binary
  must stay cgo-free and dependency-light, and `os.File.Stat`'s
  `ModeCharDevice` check is sufficient on the supported platforms); keep
  echoing the invoked command (rejected: the user just typed it, so it is
  pure noise in the compact view).
- Reason: the compact default made the tool look frozen during the exact
  stages it exists to run, because they print nothing until they finish;
  the freeze was the top piece of feedback. Confining the animation to stderr
  and making it inert on non-terminals keeps piped output byte-for-byte clean
  and the report on stdout untouched, so this is presentation only - detection,
  containment, exit codes, and every flag behave identically. Terminal
  detection via `os.File.Stat` avoids any new dependency and keeps the run
  binary cgo-free. New tests: `TestSpinnerNoOpOnNonTerminal`,
  `TestNilSpinnerIsSafe`, `TestSpinnerLifecycleIsSafe`.

## 0020 - Skip Python dependency trees and tool caches in the scan walk

- Decision: extend `skipDirNames` (`internal/analyze/walk.go`) to skip the
  Python dependency trees `env`, `.tox`, `.eggs` and the inert tool caches
  `.mypy_cache`, `.pytest_cache`, and add `isGeneratedMetadataDir` to also skip
  glob-named packaging metadata dirs (`*.egg-info`, `*.dist-info`), which an
  exact-match map cannot express. This joins the pre-existing
  `node_modules`/`vendor`/`.next`/`__pycache__`/`venv`/`.venv` skips.
- Alternatives: leave the Python trees walked (rejected: inconsistent with
  `node_modules`, which was always skipped, and floods the report with a
  dependency's own legitimate long/obfuscated-looking lines); go the other way
  and START scanning dependency trees, including `node_modules` (rejected: a
  half-measure that scans some dep code and not others is worse than a
  consistent rule, and it does not add real safety because containment already
  owns dependency risk - the scan is advisory); match `*.egg-info` by adding a
  synthetic key to the exact-match map (rejected: the name is keyed on the
  package name, so it must be a suffix test, not an exact match).
- Reason: these directories hold installed third-party package code or
  generated caches, not source an attacker hand-edits, and skipping them is
  consistent with the long-standing `node_modules` decision. The dependency
  code CAN carry a payload, but the safety property is containment: whatever a
  dependency ships runs inside the locked-down sandbox during install/import,
  and in the normal clone-then-scan flow these trees are gitignored and created
  at install time in the container, not committed - so a checked-in trojaned
  venv is the same residual exposure `node_modules` already has, not a new one.
  `dist/`/`build/` stay walked (invariant unchanged): an attacker could disguise
  a payload as a build artifact, so only the entropy heuristic skips those.
  New tests: extended `TestWalkFilesSkipsNoiseDirs`, `TestIsGeneratedMetadataDir`.

## 0021 - Two-phase install for node; fast-fail and an install timeout everywhere

- Decision (FINAL design; see the update below for how this decision
  evolved): for `meguard run`, add fast-fail flags to the default install
  commands for every ecosystem (`--fetch-retries=0` for node,
  `--retries 0 --timeout 5` for python), add a bounded `--timeout` (default
  `2m`, `0` disables) that covers both the prefetch and the in-sandbox
  install (`ExecuteOptions.InstallTimeout` / `PrefetchOptions.Timeout`, new
  `sandbox.ErrInstallTimeout`), and, for node only, make the install
  two-phase by default: a CONTAINERIZED prefetch (`npm install
  --ignore-scripts ...`, run inside its own hardened, throwaway, networked
  container with no host mounts - `sandbox.RunPrefetch` /
  `prefetchCreateArgs`) downloads the full dependency tree, then the sandbox
  installs strictly OFFLINE from that cache with the network still sealed.
  New `--no-prefetch` opts back into single-phase; an explicit `--cmd` does
  too.
- Alternatives: leave the single-phase, network-less install as-is (rejected:
  the motivating incident - a run stalling 15 minutes because `npm install`
  retried DNS against the always-denied sandbox network before giving up -
  is a real usability failure, and worse, because the install never
  completes, dependency lifecycle scripts never run at all, so meguard could
  never observe what a MALICIOUS TRANSITIVE DEPENDENCY's `postinstall` tries
  to do - a real detection gap, not just a slow one); only add the fast-fail
  flags and a timeout, without two-phase (rejected: fixes the stall but not
  the detection gap - a fast-failing single-phase install still never runs
  a single dependency script, since npm cannot begin installing anything
  without network access to resolve/fetch the tree); prefetch on the HOST
  with scripts enabled to save a step (rejected outright: that is literally
  running arbitrary repo/dependency code on the host, a direct breach of
  invariant 1); prefetch on the HOST with `--ignore-scripts` (TRIED FIRST,
  then abandoned - see the update below); run the prefetch inside a
  throwaway, network-enabled container instead (the design actually
  shipped, after the host approach proved unfixable by string-matching
  alone).
- Reason (four parts, as requested):
  1. Two-phase does not violate invariant 1: the prefetch leg passes
     `--ignore-scripts`, which suppresses every lifecycle script of the root
     package AND every dependency, so no repo or dependency code ever
     executes. Only inert, still-packed tarballs are fetched into a cache as
     a result. The actual `npm install` that *does* run scripts happens only
     in the second leg, inside the sealed sandbox, exactly like before.
  2. The sandbox egress guarantee is completely unchanged: the second leg
     installs with `--offline` while the network is still fully sealed by
     the same mechanism as every other run (`--network none` or the
     fail-closed monitor netns per invariant 4). Two-phase does not add,
     remove, or weaken any network control on the SEALED sandbox; it only
     changes WHAT gets a chance to attempt egress there (now every
     dependency's lifecycle script, not just the root package's), which is
     the entire point: an attacker who hides a payload in a transitive
     dependency's `postinstall` is now caught, logged, and dropped instead
     of never running.
  3. The prefetch container itself is the one container meguard gives a
     network, and closing that safely took three iterations:
     - First cut: prefetch ran on the HOST, guarded by stripping the
       repo-root `.npmrc` (npm resolves `.npmrc` config even under
       `--ignore-scripts`, and a hostile one could redirect the registry,
       proxy through an attacker host for SSRF, or interpolate `${ENV_VAR}`
       to exfiltrate a host secret), a minimal secret-free environment (only
       `PATH`, an isolated temp `HOME`, `GIT_ALLOW_PROTOCOL=https:http`; not
       `os.Environ()`), a pinned registry on the command line, and declining
       prefetch below npm major version 9.
     - A second security review found that `--ignore-scripts` does NOT stop
       npm from resolving a `file:`/`link:`/`portal:`/bare-path dependency
       spec, which reads and copies the referenced HOST path into
       `node_modules` during install with no script needed at all (e.g. an
       absolute `file:/etc/passwd` in `package.json`) - a host
       arbitrary-file-read, breaching invariant 2. The host-prefetch design
       was patched to parse the manifest and lockfiles read-only and decline
       to single-phase whenever any local dependency spec was present.
     - A third review showed a fixed-prefix allowlist for that parsing was
       too narrow: npm resolves ANY spec containing a path separator as a
       local install, so `x/../../etc` (no `file:` prefix) still escaped.
       The detection was broadened to mirror npm's own resolver (any
       separator or local-tarball suffix that is not a URL or `npm:` alias),
       `workspaces` globs were parsed for escapes, and a positive post-hoc
       check resolved every installed entry with `EvalSymlinks` to verify
       nothing landed outside the repo.
     - A FOURTH review (the one that ended the host approach) concluded that
       npm's local-dependency-spec surface is open-ended enough - `file:`,
       bare paths, `overrides`, `workspaces`, lockfile entries, and whatever
       resolver behavior a future npm version adds - that a host-side
       allowlist could not be trusted to have closed the class completely,
       only the instances tried so far. The fix was moved from detection to
       structure: the prefetch now runs `npm install --ignore-scripts`
       inside its OWN hardened, throwaway, NETWORKED container
       (`prefetchCreateArgs`, sharing `baseHardeningArgs` with the sealed
       sandbox and differing only in `--network bridge` vs `--network
       none`), which has NO host bind mounts. A malicious local dependency
       spec of any shape now resolves only against the CONTAINER's own
       filesystem - the host-file-read class is structurally impossible,
       not something meguard has to keep re-discovering forms of and
       guarding against. It is still safe to give this one container a
       network for the same reason as the host design: `--ignore-scripts`
       means no repo or dependency code ever runs, so the untrusted repo
       can never use that network itself. All the host-side machinery from
       the three earlier iterations (`.npmrc` stripping, the minimal
       environment, the npm-version gate, `isLocalSpec`/
       `manifestHasLocalDeps`/`nodeModulesEscapes`) has been removed; it is
       superseded, not layered on top of, the container. Only the populated
       npm cache (never `node_modules`) is copied back out of the prefetch
       container, via a tar stream through `docker exec`
       (`copyCacheOut`/`untarInto`) since `/repo` is a tmpfs and `docker cp`
       cannot read it - the same reason the repo is copied IN via a tar
       stream rather than `docker cp`. Because that tar is produced over a
       subtree whose bytes originate from the untrusted repo and is extracted
       on the HOST, `untarInto` materializes ONLY directories and regular
       files and validates each entry name stays within the destination; it
       SKIPS symlink entries entirely (a fifth review flagged that recreating
       an attacker-chosen symlink target such as `.meguard-cache/x ->
       ~/.ssh/id_rsa` would be a host symlink-plant / CWE-59), which an npm
       cache never needs. The `--ignore-scripts` no-execution claim was
       verified on the actual image (node:20-slim ships npm 10.8.2): with
       `--ignore-scripts`, none of preinstall/install/postinstall/prepare/
       prepublish run, so no repo or dependency code executes in the networked
       prefetch container.
  4. Node-only is deliberate, not an oversight: node's `--ignore-scripts`
     has a real, provably-no-code-execution mode, so it is safe to prefetch
     with a network at all. Python has no equivalent - `pip download`/
     `pip wheel` execute a source distribution's `setup.py` to resolve
     metadata, which IS code execution outside the sealed sandbox - so
     python intentionally stays single-phase, gaining only the fast-fail and
     timeout fixes. A contained (sandboxed) Python prefetch that sidesteps
     this is future work.
- Implementation notes: prefetch is best-effort throughout
  (`prefetchOutcome` in `cmd/prefetch.go`) - any failure (staging, the
  prefetch container itself, or a timeout) falls back to the ecosystem's
  single-phase install with a stated reason, never a hard failure of the
  run. A repo passed as a local path is staged into a fresh temp copy before
  prefetch (`stageForMutation`), since the populated cache is copied back
  into that staging dir, so meguard never mutates the user's working tree; a
  git clone is already an owned temp copy. The cache (`sandbox.CacheDirName`,
  `.meguard-cache`) lives inside the staged repo dir on the host once copied
  out of the prefetch container, so it travels into the SEALED sandbox with
  the existing tar-copy mechanism with no new mount, and the static scan's
  directory skip list was extended to exclude it (inert compressed blobs,
  pure noise for the analyzers).
- Update (final design, containerized prefetch): superseded the host-side
  prefetch entirely, as detailed in reason 3 above. The host approach was
  abandoned after four security-review iterations because npm's local
  dependency-spec resolution surface (`file:`, bare paths, `overrides`,
  `workspaces`, lockfile entries) is open-ended enough that a host-side
  allowlist could not be trusted to have closed it completely, only the
  forms tried. Running the prefetch inside a throwaway, no-host-mount
  container instead closes the class STRUCTURALLY: any local spec resolves
  against the container's own filesystem, never the host's, while
  `--ignore-scripts` still guarantees no repo code runs on that networked
  container, and the sealed sandbox's `--network none`/monitored egress
  denial (invariant 4) is completely unaffected. New
  `TestPrefetchCreateArgsHardening` (`internal/sandbox/args_test.go`) locks
  in that the prefetch container keeps every unconditional hardening flag
  the sealed sandbox has and differs only by network mode.

## 0022 - Force-remove the container if `docker create` itself fails

- Decision: `DockerRunner.Create` (`internal/sandbox/docker.go`) now calls
  `removeDetached(d, name, io.Discard)` before returning an error from a
  failed `docker create` CLI invocation.
- Alternatives: leave `Create` as-is and rely on the caller's cleanup
  (rejected: `Execute` only defers its `Remove` once `Create` returns a
  non-empty id, so a `docker create` that fails at the CLI level - for
  example the context is cancelled right at that boundary, or a future
  stdout-parse failure - after the daemon has already created the container
  would leak it with no code path left to clean it up); only remove on
  specific known-leaky error types (rejected: needlessly narrow; `docker rm
  -f` on a name that was never actually created is a harmless no-op, so
  removing unconditionally on any create failure is simpler and no less
  safe).
- Reason: closes a narrow gap in safety invariant 5 ("cleanup MUST run on
  install failure, panic, or Ctrl-C, for both containers"): the container
  meguard assigns its own name to before calling `docker create`, so cleanup
  can target that name even when the CLI call itself never reports an id.
  New test: `TestCreateRemovesContainerOnFailure`
  (`internal/sandbox/docker_test.go`), a fake `docker` script that fails
  `create` and records that `rm -f meguard-...` is invoked next.

## 0023 - Prefetch npm log honors compact mode; default node image to a supported LTS

- Decision: two small follow-ups to the two-phase install (decision 0021) and
  compact output (decision 0017), prompted by a real run whose terminal was
  dominated by npm noise it should not have shown.
  - The containerized prefetch leg now buffers its own npm output the same way
    the in-sandbox install log already did: captured in compact mode and
    discarded on success, flushed to stderr only if the prefetch fails, and
    streamed live under a `PREFETCH OUTPUT` header only under `-v`. Previously
    `runPrefetch` wired the prefetch command's stdout+stderr straight to the
    real stderr unconditionally, so every run - even a clean, compact one -
    printed npm's full `EBADENGINE`/deprecation wall and package count,
    burying the status checklist. Its own code comment even claimed "a compact
    run stays clean," which it did not. This is presentation only; nothing
    about what the prefetch does changed.
  - A new `PrefetchOptions.Diag` writer carries meguard's own prefetch-cleanup
    diagnostics (a `docker rm -f` failure) on the real stderr regardless of
    `-v` or the buffering, so the captured npm buffer can never swallow a
    cleanup failure on an otherwise successful prefetch. This is the exact
    split decision 0017 established for `ExecuteOptions.Diag`; applying the
    same rule to the prefetch leg keeps invariant 5's cleanup diagnostics
    visible.
  - The default node image moved from `node:20-slim` to `node:22-slim`
    (`sandbox.DefaultImage`). Node 20 reached end-of-life, so auto-detection
    was defaulting untrusted repos onto an unsupported base. `node:22-slim` is
    the current active LTS. The image is a RELAX value only (invariant 3): the
    zero-value Profile is unaffected as a security control, and an explicit
    `--image` still wins. `TestDefaultImageIsSupportedNodeLTS` pins the new
    default so a later edit cannot silently regress it to an EOL base.
- Alternatives: keep streaming the prefetch log and tell users to ignore it
  (rejected: it defeats the whole point of compact mode, and the noise is per
  transitive dependency so it scales with the repo); leave the default at
  node:20-slim and only bump per-run with `--image` (rejected: shipping an
  EOL default is exactly the stale default a security tool should not carry,
  and the warnings a mismatched engine produces are themselves noise);
  reuse the existing `Stderr` field for cleanup diagnostics instead of adding
  `Diag` (rejected: that is the field being buffered away, which is the bug
  decision 0017 already ruled out for the sealed install).

## 0024 - Runtime execution phase for `meguard run` (default on)

- Decision: after a SUCCESSFUL install (exit code 0), `run` now executes the
  repo at runtime inside the SAME sealed container by default, so a payload
  that only fires at build time or on app startup - not at
  dependency-install time - runs where the egress monitor can observe and
  drop its outbound attempts. The plan is auto-detected build-then-serve
  (`sandbox.DetectExecPlan`: node runs a `build` script then the first of
  `start`/`dev`/`serve`/`main`/`index.js`; python runs `main.py`, then
  `app.py`, then a single loose top-level `*.py`). A long-running serve step
  runs under a short OBSERVATION WINDOW (default `3s`, `--exec-window`) and
  is then stopped, since a dev server or app never exits on its own; a build
  step is bounded by `--timeout` instead, like the install. `--no-exec`
  restores install-only; `--exec-cmd` overrides the plan with one explicit
  command.
- Alternatives: keep `run` install-only indefinitely (rejected: install-only
  made `run` a glorified scan for this whole payload class - a build-time or
  startup-triggered infostealer hidden in app source, for example a
  component file or a `tailwind.config.ts`, never runs during a plain
  `npm install`, so the egress monitor reports "0 egress attempts" even for
  a genuinely malicious repo, and the static scan's flagged text is never
  corroborated by an actual observed attempt); always run the serve step to
  completion with no window (rejected: a dev server or long-running app
  never exits on its own, so this would hang every run with a `start`
  script indefinitely); run the exec phase even when the install failed
  (rejected: a broken install usually leaves the app unable to run at all,
  so running it anyway would only add noise, not signal); guess a
  framework-specific runner such as Django's `manage.py runserver`
  (rejected: that needs arguments and a bound port meguard cannot safely
  infer; a project that must be launched a specific way is run explicitly
  with `--exec-cmd`).
- Reason: this is dynamic analysis that complements the static scan rather
  than replacing it - the scan already flags an obfuscated payload as
  suspicious text on disk, and the runtime phase corroborates whether it
  actually fires, within the fixed-length build/observation window; it does
  not claim to observe every code path, only what runs during that window.
  It changes nothing about the five safety invariants: an `ExecStep` runs
  untrusted code exactly like the install command already does, inside the
  same already-sealed container, with the same no-host-mounts, fail-closed
  egress, and force-removal-on-every-path guarantees; the install-success
  gate (`code == 0`) and the observation window are the only new pieces of
  logic, and a window-elapsed stop is treated as SUCCESS, not a failure,
  since the payload has already had its chance to fire and be observed by
  then. Egress is now collected once after the LAST runtime step (not just
  after install), so a single report covers install, build, and run
  together.

## 0025 - Suppress the sealed-install log when prefetch already failed

- Decision: on the compact (non--verbose) path, `meguard run` no longer dumps
  the raw sealed-install log when the containerized prefetch (decision 0021)
  already failed. Prompted by a real run against a repo with a peer-dependency
  conflict: prefetch failed with `ERESOLVE`, its npm log was flushed as the
  root-cause diagnostic (decision 0023), and then the single-phase fallback
  installed strictly OFFLINE inside the sealed, network-less sandbox from an
  unpopulated cache, so it failed with a foregone `getaddrinfo`/`EAI_AGAIN`
  error whose actual cause was the prefetch failure already shown above it.
  The terminal therefore carried TWO npm logs for one failure: the real cause
  (ERESOLVE) and a redundant downstream consequence (EAI_AGAIN). `cmd/run.go`
  now guards the `INSTALL LOG (install exited non-zero)` block with
  `!prefetchFailed` (`prefetch.Attempted && !prefetch.OK`), so the second log
  is suppressed exactly when the prefetch log has already explained the
  failure. The compact report's `prefetch` and `install` status lines still
  record that both failed, so nothing is hidden about WHAT happened, only the
  redundant second log is dropped.
- Alternatives: also silence the `git clone` progress in compact mode
  (rejected by the maintainer: the clone output is wanted and stays as-is);
  suppress the install log for ANY install failure, not just a
  prefetch-triggered one (rejected: when prefetch did NOT run or succeeded, the
  install log is the primary and only diagnostic, so it must still show); print
  a one-line pointer back to the prefetch log instead of nothing (rejected as
  unnecessary: the compact report's `! prefetch` and `x install` lines already
  make the two-stage failure legible, and `-v` still streams every log live).
- Reason: presentation only, in the same spirit as decisions 0017 and 0023 -
  nothing about detection, containment, or the five invariants changes; a
  compact run should surface the single log that explains the failure, not
  stack a foregone downstream error on top of the real cause.
