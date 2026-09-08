# CLAUDE.md - meguard working contract

meguard is a fast, lightweight Go CLI that safely executes untrusted repositories
(for example fake-interview repos that hide infostealer or RAT payloads) inside a
locked-down container sandbox. It optimizes for fast startup, a single static
binary, and small memory. The `run` binary stays pure Go (no cgo).

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
node:20-slim) and `--cmd` (default `npm install`). Ecosystem auto-detection is
OUT of scope (TODO tier-2). `--memory` and `--cpus` are conservative defaults
that will become user-configurable; a large install may need more than 2g.

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

## Scan architecture decision (DOCUMENT ONLY for now; scan is not implemented)

Recorded so future scan work inherits it:
- scan will be built from analyzers behind a single `Analyzer` interface.
- Pure-Go analyzers (CGO_ENABLED=0): manifest (package.json/setup.py/
  pyproject.toml), entropy (base64/hex blobs, minified single-liners), regex
  (cheap first-pass matching).
- ONLY the AST analyzer (tree-sitter) needs cgo, isolated behind build tags so
  it is the sole cgo dependency and degrades to a labeled no-op when compiled
  out. Illustrative seam (do not implement):

      //go:build cgo      -> newASTAnalyzer() returns treeSitterAnalyzer
      //go:build !cgo     -> newASTAnalyzer() returns noopAnalyzer{reason:"AST needs a cgo build"}

- Two build variants ship: pure static (no AST) and cgo (full). Same binary name
  and commands.
- On the pure build, scan still runs manifest+entropy+regex; the AST no-op MUST
  announce it is disabled. A clean scan on the pure build is NEVER presented as
  "AST found nothing"; absence of AST is stated, not silent.
- `run` and `sandbox` NEVER import `analyze` or any analyzer. Purity is
  structural, enforced by `TestSandboxDoesNotImportAnalyze` in
  `internal/sandbox/import_guard_test.go`.

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
