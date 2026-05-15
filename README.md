# chaindora

> **Supply chain compromise scanner** — detect known IOCs, post-compromise
> host artifacts, suspicious dependencies, and rogue install-time code across
> npm, pip, six CI/CD platforms, and Docker.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/alessandro-bitetto/chaindora.svg)](https://pkg.go.dev/github.com/alessandro-bitetto/chaindora)

The CLI is `chdora` (the project is `chaindora`). It answers one question:
**"Did I get hit by a supply chain attack?"**

It runs three commands:

- **`chdora scan`** — inventories every locked dependency in a project,
  matches them against [OSV.dev](https://osv.dev) and a curated incident
  pack, walks CI YAMLs for compromised actions/orbs/pipes/images, and
  applies behavioral heuristics.
- **`chdora forensics`** — hunts post-compromise artifacts on the host:
  leaked credentials, shell-rc tampering, and worm-deployed files like
  `shai-hulud-workflow.yml`.
- **`chdora ci`** — same scan, gated for CI/CD pipelines: autodetects
  GitHub Actions / GitLab / CircleCI / Bitbucket / Azure / Drone / Jenkins,
  applies `--fail-on critical,high`, writes a SARIF sidecar for upload.

## Quick example

```text
$ chdora scan .
inventoried 142 packages from 11 sources
3 finding(s):

  [CRITICAL] [incident-pack] pkg:npm/%40ctrl/tinycolor@4.1.1
    SHAI-HULUD-2025 — Shai-Hulud npm worm
    source: package-lock.json
    ref: https://socket.dev/blog/shai-hulud-npm-worm

  [HIGH] [osv-ioc] pkg:npm/lodash@4.17.20
    GHSA-35jh-r3h4-6jhm — Command Injection in lodash
    source: package-lock.json

  [MEDIUM] [heuristic:typosquat] pkg:pypi/requets@2.0.0
    HEUR-TYPOSQUAT — PyPI package "requets" is 1 edit(s) away from popular package "requests". Verify this is not a typosquat.
```

## Install

### Pre-built binary (recommended)

Download the archive for your OS/arch from the
[Releases page](https://github.com/alessandro-bitetto/chaindora/releases),
extract, and move `chdora` somewhere on your `$PATH` (the archive is
named `chaindora_<version>_<os>_<arch>` after the project; the binary
inside is `chdora`):

```sh
# macOS / Linux example
curl -L https://github.com/alessandro-bitetto/chaindora/releases/latest/download/chaindora_<version>_<os>_<arch>.tar.gz | tar xz
sudo mv chdora /usr/local/bin/
```

Each release publishes a `chaindora_<version>_checksums.txt` for verification:

```sh
shasum -a 256 -c chaindora_<version>_checksums.txt
```

### From source

```sh
go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
```

Requires Go 1.22+. After `go install`, make sure your Go bin directory is on
`$PATH` so the binary is reachable as `chdora`:

```sh
# One-off check
ls "$(go env GOPATH)/bin/chdora"

# Add to PATH (persist by adding to ~/.zshrc or ~/.bashrc)
export PATH="$PATH:$(go env GOPATH)/bin"
```

If you see `command not found: chdora` right after a successful install,
this is the fix.

## Commands

### `chdora scan [path]`

Project-tree scan. Runs OSV.dev queries, incident-pack matching, and
behavioral heuristics by default.

```sh
chdora scan .                                # scan current directory
chdora scan ./my-project --format sarif      # SARIF 2.1.0 to stdout
chdora scan . --skip-osv                     # offline (no OSV queries)
chdora scan . --fresh-popular                # also check publish dates
chdora scan . --incidents ./my-incidents     # custom incident pack
chdora scan . --exclude testdata,vendor      # skip directories by basename
```

### `chdora audit`

The one-word "scan everything on this machine" entry point. Walks `--root`
(default `$HOME`) for every project manifest and runs a full scan against
each; enumerates globally-installed packages, browser/IDE extensions, and
user-level persistence (cron / launchd / systemd / Scheduled Tasks);
snapshots/diffs `~/.ssh/authorized_keys` against a baseline; plus the
default host-state checks (credential files, shell rc tampering, file
artifact hunt). Equivalent to a fully-flagged `chdora forensics
--scan-projects $HOME --deep --extensions --persistence --ssh-check`.

```sh
chdora audit                              # full audit, all detectors on
chdora audit --root /Users/me/code        # narrower root
chdora audit --skip-deep --skip-extensions   # disable individual detectors
chdora audit --format json > audit.json   # pipe-friendly
chdora audit --fix-plan                   # show remediation plan
```

Each detector can be individually disabled with its `--skip-X` flag (see
`chdora audit --help`).

### `chdora forensics`

Host-state hunt. Inspects `~/.npmrc` / `~/.pypirc` / `~/.docker/config.json`
/ `~/.aws/credentials` / `~/.gem/credentials` / `~/.cargo/credentials.toml`
for leaked tokens, scans **shell rc files** (`.bashrc`, `.zshrc`,
`.profile`, …) and **PowerShell profiles** (cross-platform `pwsh` plus
Windows-specific Documents paths) for `curl|bash` / `iex (irm …)` /
`eval $(base64 …)` / AV-bypass patterns, lists Windows Credential
Manager blobs when present, and hunts incident-pack file artifacts
(e.g. `shai-hulud-workflow.yml`) across `$HOME`.

```sh
chdora forensics                             # tokens + shell rc + PowerShell + artifact hunt
chdora forensics --hunt-root ~/code          # narrower artifact hunt
chdora forensics --skip-hunt                 # tokens + shell rc only
chdora forensics --format json | jq          # pipe to jq

# Optional add-on detectors (each requires its own flag):
chdora forensics --ssh-check                 # baseline/diff ~/.ssh/authorized_keys
chdora forensics --persistence               # cron, launchd, systemd, Scheduled Tasks
chdora forensics --extensions                # Chromium + VSCode/Cursor extensions

# Full-machine mode: discover EVERY project on disk and scan each.
chdora forensics --scan-projects ~ --verbose
chdora forensics --scan-projects ~/code --skip-osv --skip-heuristic

# Deep mode: also enumerate globally-installed npm/pip/brew/apt packages.
chdora forensics --deep --verbose

# Combine all add-ons for a comprehensive single-machine audit:
chdora forensics --scan-projects ~ --deep --extensions --persistence --ssh-check
```

The `--scan-projects <root>` flag walks the filesystem for project
manifests (`package.json`, `requirements.txt`, `Cargo.toml`, `go.mod`,
`Dockerfile`, `.gitlab-ci.yml`, `.circleci/`, …), deduplicates nested
manifests, and runs a full scan against each discovered project root
alongside the host-state checks. Skips `node_modules` / `.venv` /
`.git` / `vendor` / `target` / `dist` / caches / `Library` / `AppData`
by default.

### `chdora update`

Refreshes the curated incident pack from the upstream repo into
`~/.chaindora/incidents/`. **Without periodic updates, chaindora only knows
about the incidents that existed when you installed the binary** — run this
command after every reported supply-chain attack against an ecosystem you
use (or set up a daily cron / scheduled task).

```sh
chdora update                                # fetch from upstream
chdora update --dry-run                      # report changes only
chdora update --dest /opt/chaindora/incidents  # custom location
chdora update --source https://api.github.com/repos/myfork/chaindora/contents/incidents?ref=main
```

`chdora scan` automatically prefers `~/.chaindora/incidents/` over the
bundled `./incidents/` directory if both exist, so an `update` immediately
takes effect on the next scan.

### `chdora upgrade`

Self-upgrades the binary. Queries the GitHub Releases API, picks the
goreleaser archive matching the current GOOS/GOARCH, verifies its
SHA-256 against the published checksums file, and atomically replaces
the running binary. **`chdora update` refreshes the *incident pack*;
`chdora upgrade` refreshes the *binary itself*** — run both periodically.

```sh
chdora upgrade                                # latest release
chdora upgrade --check                        # report only, no download
chdora upgrade --dry-run                      # download + verify, no swap
chdora upgrade --version v0.4.0               # pin to a specific tag
chdora upgrade --force                        # re-install / override pkg-mgr guard
```

If the binary path looks Homebrew- or snap-managed, `upgrade` refuses
with a hint to use the package manager instead (override with `--force`).
On Windows the previous `.exe` is parked alongside as `chdora.exe.old`
because Windows refuses to overwrite a running executable.

### `chdora ci [path]`

CI gate. Autodetects the running CI from environment variables, picks an
appropriate output format, applies `--fail-on critical,high` by default,
and optionally writes a SARIF sidecar for code-scanning dashboards.

```sh
chdora ci .                                  # autodetect everything
chdora ci . --fail-on any                    # strictest gate
chdora ci . --sarif chdora.sarif          # also write a sidecar
chdora ci . --fail-on none                   # informational, always 0
```

A typical GitHub Actions step:

```yaml
- run: chdora ci . --sarif chdora.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: chdora.sarif
```

See [docs/ci-integration.md](./docs/ci-integration.md) for recipes covering
GitLab CI, CircleCI, Bitbucket Pipelines, Azure Pipelines, and Jenkins.

## Detection layers

| Layer | Detector | Highlights |
|---|---|---|
| Known IOC | OSV.dev | Full coverage of npm, PyPI, and OCI (Docker base images); CVSS v3 severity parsing for real-world prioritization |
| Curated incidents | `incident-pack` | 14+ entries covering Shai-Hulud, qix chalk/debug, ctx PyPI, ua-parser-js, event-stream/flatmap-stream, eslint-scope, colors+faker sabotage, node-ipc / peacenotwar, lottie-player, python3-dateutil + jeIlyfish typosquats, torchtriton dep-confusion, ultralytics, xz-utils (CVE-2024-3094), Great Suspender — with package-version matches, `"*"` wildcards for pure-malware namespaces, file-artifact globs, `safe_version` upgrade pins, and `post_compromise` rotation guidance. [Contribute new entries.](./docs/incident-pack.md) |
| Host forensics | `hostforensics:*` | Credential files, shell rc tampering, Shai-Hulud workflow files, all incident-pack file artifacts across `$HOME` |
| Heuristics | `heuristic:*` | Unpinned CI refs, `curl\|bash` in CI scripts, npm install scripts, typosquats (Levenshtein vs top-N popular), dependency confusion, fresh-popular versions (opt-in) |

Severity for OSV findings comes from a fully implemented CVSS v3 base-score
calculator (see [internal/osv/cvss.go](./internal/osv/cvss.go)).

## Supported ecosystems

| Ecosystem | Manifests | OSV |
|---|---|---|
| npm | `package-lock.json` (v1/v2/v3), `yarn.lock` (v1 + Berry), `pnpm-lock.yaml` | yes |
| PyPI | `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock` | yes |
| Docker | `Dockerfile`, `docker-compose.yml`, every CI YAML's `image:` field | yes (OCI) |
| GitHub Actions | `.github/workflows/*.yml` | no (incident pack + heuristics) |
| Gitea Actions | `.gitea/workflows/*.yml` | no (incident pack + heuristics) |
| GitLab CI | `.gitlab-ci.yml` (`include:`) | no |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` (`pipe:`) | no |
| CircleCI Orbs | `.circleci/config.yml` (`orbs:`) | no |
| Azure Pipelines | `azure-pipelines.yml` (`task:`) | no |
| Drone / Woodpecker | `.drone.yml` / `.woodpecker.yml` | via Docker `image:` |

Findings normalize to [Package URLs (PURLs)](https://github.com/package-url/purl-spec)
on top of a SARIF-compatible schema.

## Output formats

```sh
chdora scan . --format text     # human-readable (default)
chdora scan . --format json     # pretty JSON
chdora scan . --format jsonl    # one finding per line (for log shippers)
chdora scan . --format sarif    # SARIF 2.1.0 (GitHub code-scanning et al.)
chdora scan . --format github   # ::error file=...,line=...:: annotations
```

## Platform support

| OS | Status |
|---|---|
| Linux (amd64 / arm64) | Tier 1 — full support |
| macOS (amd64 / arm64) | Tier 1 — full support |
| Windows (amd64 / arm64) | Tier 1 — cross-compiles cleanly; host forensics includes PowerShell profile + Credential Manager checks. CI matrix coming with the GitHub Actions workflow. |

## Roadmap

- **v0.2** (in progress) — `chdora update` for incident-pack refresh
  (shipped), Windows-equivalent forensics (shipped), full-machine scan
  via `forensics --scan-projects` and `forensics --deep`, signed
  incident-pack tarballs, GitHub Actions CI on the repo itself.
- **v0.3** — Static AST scan of installed `node_modules` /
  `site-packages` for install-time exfiltration patterns (eval-of-base64,
  hardcoded webhooks, `child_process` + network in postinstall, …).
- **v0.4** — Server mode: scheduled fleet scans, findings DB, webhook
  ingest.
- **v0.5** — Expanded ecosystems: RubyGems, crates.io, Go modules,
  Maven Central.

## Contributing

The most valuable contribution is **adding entries to the [curated
incident pack](./incidents/)** — see [docs/incident-pack.md](./docs/incident-pack.md)
for the PR flow.

For everything else, see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

Found a vulnerability in `chaindora` itself? See [SECURITY.md](./SECURITY.md).

## License

[Apache-2.0](./LICENSE)
