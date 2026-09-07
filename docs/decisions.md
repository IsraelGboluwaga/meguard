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

## 0012 - Ecosystem auto-detection from repo manifests

- Decision: When `--image` / `--cmd` are unset, detect the ecosystem by reading
  the repo's top-level manifest files (`sandbox.DetectEcosystem`) and supply the
  image + install command. Ordered detectors, first match wins: node before
  python; within python, `requirements.txt` before a project manifest. No match
  falls back to the locked-down defaults; an explicit flag always overrides.
  Reverses the earlier "auto-detection is out of scope (tier-2)" note.
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
