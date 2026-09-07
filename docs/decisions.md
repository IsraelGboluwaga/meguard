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
