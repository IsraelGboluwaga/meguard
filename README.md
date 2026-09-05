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
   container tmpfs with `docker cp`. The container has no route to host secrets.
3. Sandbox defaults are locked down; configuration only ever RELAXES. The
   zero-value sandbox Profile is the safest one. A forgotten field cannot open a
   hole.
4. Network is `--network none`. No egress at all.
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

Build from source (pure static, cgo-free `run` binary):

    CGO_ENABLED=0 go build -o meguard .

Or install with Go:

    go install github.com/IsraelGboluwaga/meguard@latest

See [docs/launch.md](docs/launch.md) for both build variants, release steps, and
verification.

## Usage

    meguard run <repo-url-or-path> [--image IMAGE] [--cmd "INSTALL CMD"]

`run` accepts a git URL (cloned to a temp dir that is always cleaned up) or a
local path (copied, never bind mounted).

Examples:

    # Default: Node repo, runs `npm install` inside node:20-slim
    meguard run https://github.com/some/suspicious-repo.git

    # A local path
    meguard run ./downloaded-take-home

    # A Python repo
    meguard run ./py-repo --image python:3.12-slim --cmd "pip install -r requirements.txt"

meguard prints a pre-run notice listing the active protections, streams the
sandbox output under a labeled section, then prints a result with the install
exit code.

Only two values are ecosystem-specific: `--image` (default `node:20-slim`) and
`--cmd` (default `npm install`). Ecosystem auto-detection is not implemented yet.
`--memory` and `--cpus` are conservative internal defaults (2g / 2 CPUs) that
will become user-configurable; a large install may need more than 2g.

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
