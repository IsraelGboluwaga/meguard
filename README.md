# meguard

Safely execute untrusted repositories inside a locked-down container sandbox.

meguard is a fast, lightweight Go CLI for running repos you do not trust, for
example fake-interview repos that hide infostealer or RAT payloads in
`postinstall` hooks or obfuscated blobs. It clones or copies the repo into a
hardened container and runs the install command there. Repo code never touches
your host.

## Safety model

The five invariants meguard is built to guarantee:

1. Repo code NEVER runs on the host. meguard does `git clone` only (cloning does
   not run install hooks); all execution happens inside the container.
2. NO host bind mounts of the repo or `$HOME`. The repo is copied INTO a
   container tmpfs (streamed in as a tar through `docker exec`, because Docker
   refuses `docker cp` into a read-only container). The container has no route to
   host secrets.
3. Sandbox defaults are locked down; configuration only ever RELAXES. The
   zero-value sandbox Profile is the safest one. A forgotten field cannot open a
   hole.
4. Network is `--network none`. No egress at all. (Opt-in `--inspect-egress`
   keeps egress fully denied but makes each blocked attempt visible; see below.)
5. The container is force-removed (`docker rm -f`) on success, install failure,
   panic, or Ctrl-C.

Under the hood, each `run` create these hardening controls on the container:
non-root user, all capabilities dropped, `no-new-privileges`, read-only root
filesystem, tmpfs-only writable paths, a PID cap, memory and CPU ceilings, and
no network.

## Install

meguard needs a Docker-COMPATIBLE runtime on PATH. You do NOT need Docker
Desktop. Any of these work with no configuration change:

- Docker Engine / Docker Desktop
- OrbStack (macOS, lightweight) - recommended for lightness
- Colima (macOS/Linux, lightweight) - recommended for lightness
- Podman (daemonless, rootless) - recommended for security

Install with Go (works today):

    go install github.com/IsraelGboluwaga/meguard@latest

Or build from source (pure static, cgo-free `run` binary):

    CGO_ENABLED=0 go build -o meguard .

Homebrew (available once the first release is tagged; see docs/launch.md):

    brew install IsraelGboluwaga/tap/meguard

Check the version:

    meguard --version

See [docs/launch.md](docs/launch.md) for the release pipeline, both build
variants, and verification.

## Usage

    meguard run <repo-url-or-path> [--image IMAGE] [--cmd "INSTALL CMD"] [--runtime CLI] [--inspect-egress]

`run` accepts a git URL (cloned to a temp dir that is always cleaned up) or a
local path (copied, never bind mounted).

Examples:

    # Default: Node repo, runs `npm install` inside node:20-slim
    meguard run https://github.com/some/suspicious-repo.git

    # A local path
    meguard run ./downloaded-take-home

    # A Python repo
    meguard run ./py-repo --image python:3.12-slim --cmd "pip install -r requirements.txt"

    # Rootless runtime (recommended for genuinely hostile code)
    meguard run ./suspicious-repo --runtime podman

    # See what the repo TRIED to reach (every attempt is still blocked)
    meguard run ./suspicious-repo --inspect-egress

meguard prints a pre-run notice listing the active protections and the runtime
enforcing them, streams the sandbox output under a labeled section, then prints
a result with the install exit code.

Only two values are ecosystem-specific: `--image` (default `node:20-slim`) and
`--cmd` (default `npm install`). Ecosystem auto-detection is not implemented yet.
`--memory` and `--cpus` are conservative internal defaults (2g / 2 CPUs) that
will become user-configurable; a large install may need more than 2g.

### Inspecting blocked egress (`--inspect-egress`)

By default `--network none` gives the container no network stack at all, so a
malicious repo cannot phone home - but a blocked attempt also leaves nothing to
report. `--inspect-egress` opts into a still-no-egress but OBSERVABLE mode: a
hardened monitor sidecar seals a network namespace with no route out (only a
logging sinkhole), the sandbox joins that namespace, and every outbound TCP
connection attempt (to any IP:port, so hardcoded C2 addresses are caught too) and
DNS lookup is logged and dropped. Nothing ever leaves the host; you just get to
see what the repo tried:

    egress: 2 outbound attempt(s) BLOCKED (logged and dropped; none reached the network):
      - BLOCKED tcp 185.220.101.5:443
      - BLOCKED dns api.evil-c2.net

A clean run states "0 outbound attempts observed" explicitly - absence is stated,
never silent. The monitor image defaults to `nicolaka/netshoot` and is
overridable with `--monitor-image`; it must provide `ip`, `iptables`, and
`tcpdump`. The sandbox itself gains no privileges - only the monitor (which runs
no repo code) is granted the two network capabilities it needs. Egress inspection
is off by default so the safest posture (no network stack) stays the default.

### Choosing a runtime (the trust boundary)

The container daemon is the trust boundary: meguard's hardening flags are only
as strong as the runtime that enforces them, and the shared host kernel is the
ceiling. `--runtime` selects any Docker-compatible CLI (default `docker`). For
genuinely hostile code, prefer a rootless runtime such as `--runtime podman` so
that a container escape lands as an unprivileged user rather than as host root.
meguard does not defend against a host-kernel or root-daemon escape; a rootless
runtime is the single biggest reduction in blast radius available today.

## Troubleshooting

If no Docker-compatible runtime is running, `meguard run` fails immediately
(before cloning anything) with:

    meguard: no Docker-compatible runtime is available: ...

followed by the list of runtimes that satisfy the requirement. Start your runtime
and check it with one of `orbstack status`, `colima status`, `podman info`, or
`docker info`, then retry. You do not need Docker Desktop.

## scan (coming later, not in this release)

A future `scan` command will statically analyze a repo before you ever run it,
using analyzers behind a single interface (manifest, entropy, regex, and an AST
analyzer). It will ship in two build variants:

- a full build (includes the tree-sitter AST analyzer, needs cgo), and
- a zero-dependency pure-static build (omits AST; still runs manifest, entropy,
  and regex).

On the pure build, the absence of AST is stated explicitly, never presented as
"AST found nothing". `run` and its sandbox never depend on scan.

## Contributing

See [CLAUDE.md](CLAUDE.md) for the working contract, coding standards, and the
standing rule that docs and CHANGELOG are updated in the same change as code.

## More docs

- [docs/documentation.md](docs/documentation.md) - architecture and threat model
- [docs/launch.md](docs/launch.md) - build variants, release, and deploy
- [docs/decisions.md](docs/decisions.md) - decision log
- [CHANGELOG.md](CHANGELOG.md) - changes
