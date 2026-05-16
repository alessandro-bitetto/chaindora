# chaindora

Supply-chain attack prevention and detection for software projects.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/alessandro-bitetto/chaindora.svg)](https://pkg.go.dev/github.com/alessandro-bitetto/chaindora)
[![Release](https://img.shields.io/github/v/release/alessandro-bitetto/chaindora)](https://github.com/alessandro-bitetto/chaindora/releases)

The project is **chaindora**. The CLI binary is **`chdora`**. Apache-2.0,
single static Go binary, no agents, no daemons, no telemetry.

`chaindora.dev` (in progress) will host the long-form documentation.
This README is the on-ramp.

---

## What it does

chaindora has **two modes** that are complementary. Pick the one that
matches what you need — or run both side by side.

| Mode | When it runs | What it does | Command |
|---|---|---|---|
| **Prevention** | Before `npm install` writes bytes | Resolves the full transitive install tree across **42 package managers**, runs 10 independent checks against every node, refuses the install if any node fails | `chdora gate ...` |
| **Detection** | After packages are already on disk | Scans lockfiles, host state, and CI manifests for indicators of a compromise that already happened | `chdora scan` / `audit` / `forensics` / `ci` |

Both modes share the same incident pack, the same OSV.dev integration, and
the same finding format. They are complementary: prevention catches new
attacks at the install boundary; detection catches sleepers, late-discovered
malware, and the inventory you already installed before chaindora existed.

---

## What it catches

| Class | Detection | Prevention |
|---|:---:|:---:|
| Packages in OpenSSF Malicious Packages feed (`MAL-*`) | yes | yes |
| Known CVEs on dependencies (`GHSA-*` / `CVE-*` via OSV.dev) | yes | yes (warn) |
| Versions published less than 72h ago | — | yes |
| Account takeover (publisher changed since prior version) | — | yes |
| Sleeper-pattern indicators (obfuscation, install-script payloads, eval-of-dynamic, base64-encoded URLs) | — | yes |
| Suspicious change between version bumps (new postinstall, new `child_process` import) | — | yes |
| Brand-new packages / single-version maintainers / multi-month dormancy | — | yes |
| Compromised CI components (unpinned actions, curl-pipe-shell in scripts) | yes | — |
| Host-state compromise indicators (leaked tokens, shell rc tampering, worm-deployed files) | yes | — |
| Post-compromise persistence (cron, launchd, systemd, Scheduled Tasks) | yes | — |
| Compromised browser / VS Code extensions | yes | — |
| Republished version with different bytes (maintainer-account compromise) | — | yes |

Scope: prevention targets what is detectable at install time — known-malicious
packages, suspicious publisher/maintainer changes, freshly published versions,
install-script payloads, obfuscated or eval-heavy bundles. Sleeper attacks
that masquerade as legitimate code for years (xz-utils class) only become
visible after community detection lands; for those the detection mode plus
auto-rollback applies retroactively.

---

## Install

### Pre-built binary (recommended)

Pick the matching archive from the [Releases page](https://github.com/alessandro-bitetto/chaindora/releases/latest),
extract, place `chdora` on `$PATH`. Replace `0.14.0` with the version you
want; `latest` works as a redirect for the most recent tag.

```sh
# macOS, Apple Silicon
curl -L https://github.com/alessandro-bitetto/chaindora/releases/latest/download/chaindora_0.14.0_darwin_arm64.tar.gz | tar xz
sudo mv chdora /usr/local/bin/

# macOS, Intel
curl -L https://github.com/alessandro-bitetto/chaindora/releases/latest/download/chaindora_0.14.0_darwin_amd64.tar.gz | tar xz
sudo mv chdora /usr/local/bin/

# Linux, x86_64
curl -L https://github.com/alessandro-bitetto/chaindora/releases/latest/download/chaindora_0.14.0_linux_amd64.tar.gz | tar xz
sudo mv chdora /usr/local/bin/

# Linux, ARM64
curl -L https://github.com/alessandro-bitetto/chaindora/releases/latest/download/chaindora_0.14.0_linux_arm64.tar.gz | tar xz
sudo mv chdora /usr/local/bin/

# Windows, x86_64 (PowerShell)
Invoke-WebRequest -Uri "https://github.com/alessandro-bitetto/chaindora/releases/latest/download/chaindora_0.14.0_windows_amd64.zip" -OutFile chdora.zip
Expand-Archive chdora.zip -DestinationPath .
Move-Item chdora.exe "$env:USERPROFILE\bin\chdora.exe"   # ensure this dir is on PATH

chdora --version
```

Each release publishes a `chaindora_0.14.0_checksums.txt`. Verify before running:

```sh
curl -LO https://github.com/alessandro-bitetto/chaindora/releases/latest/download/chaindora_0.14.0_checksums.txt
shasum -a 256 -c chaindora_0.14.0_checksums.txt
```

### From source

```sh
go install github.com/alessandro-bitetto/chaindora/cmd/chdora@latest
export PATH="$PATH:$(go env GOPATH)/bin"   # if `command not found: chdora`
```

Requires Go 1.22+.

### Self-upgrade

```sh
chdora upgrade               # latest tagged release
chdora upgrade --check       # report only, don't download
chdora upgrade --version v0.14.0
```

`upgrade` refuses on Homebrew-managed binaries — use `brew upgrade` there.

---

## Mode 1: Prevention (`chdora gate`)

The gate sits between you and the package registry. Every `npm install`
(or `dotnet add package`, `composer require`, `cargo add`, `bundle add`,
`pod install`, `mix deps.get`, `gradle build`, … — **42 package managers
across 20+ language ecosystems**) resolves the full transitive tree, runs
every node through a stack of ten independent checkers, and refuses the
install if any node fails the configured policy. Fail-closed by design:
network errors block, not pass.

### Activating the gate

```sh
chdora gate install
# Add to ~/.zshrc or ~/.bashrc:
export PATH="$HOME/.chaindora/bin:$PATH"
```

In a fresh shell, every `npm install <pkgs>` now routes through chaindora.
`npm test`, `npm run build`, `npm uninstall` etc. pass through unchanged.

```sh
chdora gate status            # which managers are gated, is the shim on PATH
chdora gate disable           # remove the shims
```

Without the shim you can still gate ad-hoc:

```sh
chdora gate exec npm install lodash@4.17.21
chdora gate check lodash@4.17.21        # single-package CI check
```

### What the gate actually does

For every `(ecosystem, name, version)` in the resolved tree:

| Checker | Verdict logic |
|---|---|
| `allowlist` | Approve if listed in `chaindora.yml` allow; Block if listed in deny; otherwise pass through to the next checker |
| `osv-malicious` | Block on OpenSSF `MAL-*` match; Warn on `GHSA-*` / `CVE-*` |
| `cooldown` | Block if version published less than 72h ago (configurable) |
| `publisher-change` | Warn if `_npmUser` differs from the prior version's; first-publish-ever also warns |
| `maintainer-trust` | Warn on soft signals: <30d since first publish, <3 total versions, >6mo dormancy gap |
| `provenance` | Warn on regression — a package that previously had sigstore / sumdb / GPG attestation and stopped. `--require-provenance` upgrades to Block |
| `static-pattern` | Downloads the tarball, scans for curl-pipe-shell in scripts, `eval(<dynamic>)`, base64-encoded URLs, 256+ char high-entropy blobs. Score ≥3 → Block, ≥1 → Warn |
| `version-diff` | Scores the *delta* in static-pattern hits between requested and prior version. Catches "previously clean, now malicious" without false-positiving on libraries that always used eval |
| `git-url` | For `npm install user/repo`, `pip install git+...`, CMake `FetchContent` etc.: host-tier + ref-pin + transport-scheme evaluation. 40-hex SHA on a well-known host = Approve; branch refs / unknown hosts / `http://` = Block under Strict |
| `republish-guard` | Block when a previously-cached `(name, version)` reappears with a DIFFERENT content hash. Catches the maintainer-account-takeover pattern where an attacker republishes a known-good version with malicious bytes. Driven by `~/.chaindora/gate-cache/` |

Per-package decision = worst Verdict across all checkers. Whole-install
decision = worst per-package decision.

### Policies

- **Strict** (default): block on `Block`, `Warn`, and `Unknown` (fail-closed).
- **Lenient**: block only on `Block`; allow `Warn` through with a notice.
- **Allow-offline**: also allow `Unknown` through; appropriate for CI runs
  with no registry access. Disables fail-closed.

```sh
chdora gate exec --lenient npm install lodash      # one-shot
chdora gate exec --allow-offline npm install ...   # CI with no network
```

Persistent overrides go in `chaindora.yml` (next section).

---

## Mode 2: Detection (`scan` / `forensics` / `audit` / `ci`)

Four detection commands. The difference is **what they look at**, not how.

| Command | Looks at | Use when |
|---|---|---|
| **`chdora scan <path>`** | One project tree — its lockfiles, manifests, CI YAMLs | You want to audit a specific repo |
| **`chdora forensics`** | The host machine's persistent state — credential files, shell rc, persistence entries, SSH keys, browser/IDE extensions, globally-installed packages | You suspect a host-level compromise, or after responding to one |
| **`chdora audit`** | Everything: `forensics` + every project tree it can find under `$HOME` (or `/` with `--whole-machine`) | Full single-machine sweep — the "is my laptop OK?" command |
| **`chdora ci <path>`** | Same as `scan`, but tuned for CI: autodetects the CI env, applies `--fail-on critical,high`, emits SARIF | Project-level gate inside GitHub Actions / GitLab / CircleCI / etc. |

All four emit identical `Finding` objects. The four commands just differ in
what populates the inventory.

### Finding categories

Each finding belongs to exactly one category. Four categories total:

| Category | What it is | Detector(s) | Example |
|---|---|---|---|
| **Supply-chain attack** | Confirmed malicious package or worm artifact | `incident-pack`, OSV `MAL-*`, evidence-based heuristics | `@ctrl/tinycolor@4.1.1` (Shai-Hulud) |
| **Dependency CVE** | Known security advisory on a normal dependency | OSV `GHSA-*` / `CVE-*` | `lodash@4.17.20` (CVE-2021-23337) |
| **Configuration risk** | Setup that widens attack surface but isn't itself compromised | `heuristic:unpinned`, `heuristic:cishell` | Unpinned `actions/checkout@main` in a workflow |
| **Host state** | Indicator of post-compromise activity on the host | `hostforensics:*` | `~/.npmrc` contains a leaked token; `shai-hulud-workflow.yml` found at `$HOME` |

### Hiding categories from output

By default scan/audit/forensics/ci print every category. The
`--exclude-<category>` flags hide whole sections from the rendered output
without skipping the detection itself (the findings still exist in
`--format=json` output):

```sh
chdora scan . --exclude-cves               # hide the dependency-CVE section
chdora audit --exclude-config              # hide unpinned-action warnings
chdora audit --exclude-host                # hide credential-file warnings
chdora audit --exclude-supply-chain        # hide the incident-pack section (rare)
```

`--exclude-cves` is the most useful: it lets you scan a project for
*supply-chain attacks* without drowning in the dependency-CVE noise that
already lives in your `npm audit` workflow.

### Skipping directories during walks

A separate flag, `--exclude <basename>`, controls which directories the
inventory walker skips:

```sh
chdora scan . --exclude testdata,vendor
chdora audit --exclude node_modules,.venv     # already skipped by default
```

By default the walker skips: `node_modules`, `.venv`, `venv`, `.git`,
`vendor`, `target`, `dist`, `build`, `Library`, `AppData`, plus
`testdata/` inside chaindora's own source tree.

### Skipping detector layers

The `--skip-<layer>` flags disable an entire detector across the run:

```sh
chdora scan . --skip-osv          # no network — offline scan
chdora scan . --skip-incidents    # don't match against the incident pack
chdora scan . --skip-heuristic    # no behavioral heuristics
chdora audit --skip-deep          # don't enumerate globally-installed pkgs
chdora audit --skip-ssh-check     # don't snapshot ~/.ssh/authorized_keys
```

`--offline` is a meta-flag equivalent to `--skip-osv --skip-registry`.

### Output formats

```sh
chdora scan . --format text           # default; human-readable
chdora scan . --format json           # pretty JSON array
chdora scan . --format jsonl          # one finding per line; log-shipper friendly
chdora scan . --format sarif          # SARIF 2.1.0 — GitHub code-scanning, GitLab, etc.
chdora scan . --format github         # ::error file=...,line=...:: annotations
```

Text output goes to stdout; diagnostic / progress output goes to stderr.
`chdora scan . --format json | jq` works without filtering.

---

## Configuration: `chaindora.yml`

A per-project file at the repo root configures gate policy and allow/deny
lists. Discovered by walking up from cwd. Optional — sensible defaults
work without one.

```yaml
# Gate policy
cooldown_hours: 72          # block versions less than this old (gate)
allow_on_warn: false        # Strict (true → Lenient)
allow_on_unknown: false     # fail-closed (true → --allow-offline default)

# Per-(ecosystem, package) allow/deny
allow:
  npm:
    - "lodash@4.17.21"          # exact version
    - "@my-org/internal-utils"  # any version; we trust the scope
    - "react"                   # any version
  pypi:
    - "requests"
deny:
  npm:
    - "moment"                  # standardized on date-fns
```

Allow entries skip every gate check. Deny entries block at the gate
regardless of other check results. Both are evaluated per-(ecosystem,
package), so `lodash` allowed for `npm` does not silently allow
`lodash` for `pypi`.

---

## Remediation: `fix` and `plans`

Detection produces findings. Findings produce fix plans. Fix plans can be
applied immediately, saved for later, or shared with a coworker.

```sh
# 1. Scan and save the fix plan
chdora audit --save-plan
# → [chdora] 142 fix(es) saved to plan 2026-05-15-a558

# 2. Manage saved plans
chdora plans list
chdora plans show 2026-05-15-a558
chdora plans prune --older-than 30d

# 3. Apply later (in a different shell / different day / different person)
chdora fix --plan 2026-05-15-a558 --yes
chdora fix --plan 2026-05-15-a558 --yes --aggressive    # also semi-safe fixes
chdora fix --plan 2026-05-15-a558 --dry-run             # describe without executing

# Or apply from a saved findings.json without ever calling --save-plan
chdora scan . --format json > findings.json
chdora fix --from findings.json --yes
```

Fix categories — only `safe` runs without `--yes`; `semi-safe` requires
`--aggressive`; `unsafe` and `manual` are never executed:

| Category | Example | Auto-applied? |
|---|---|---|
| `safe` | `npm install -g pkg@latest` (global upgrade, no project impact) | with `--yes` |
| `semi-safe` | `cd /proj && npm install pkg@^X.Y.Z` (in-major caret pin) | with `--yes --aggressive` |
| `unsafe` | Anything requiring `sudo` | Never (manual steps printed) |
| `manual` | Rotate credentials, edit shell rc, remove SSH keys | Never (manual steps printed) |

Project-lockfile upgrades pin to the minimum-fixed-version-in-major
(`^X.Y.Z`) to avoid breaking peer dependencies. Package-level dedup
collapses N CVE plans on the same package into one upgrade pinned to
the highest required version. A preflight check skips fixes whose
target version is already satisfied by the current `package-lock.json`.

---

## CI integration

Drop into any pipeline as a non-blocking warning or a hard gate:

```yaml
# GitHub Actions
- run: chdora ci . --sarif chdora.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: chdora.sarif
```

```yaml
# GitLab CI
chaindora-scan:
  script: chdora ci . --format json > chdora.json
  artifacts:
    paths: [chdora.json]
```

`chdora ci` autodetects GitHub Actions, GitLab CI, CircleCI, Bitbucket
Pipelines, Azure Pipelines, Drone, and Jenkins from their respective env
vars, and picks an appropriate output format. Exit codes:

- `0` — no findings at or above `--fail-on` (default: `critical,high`)
- `1` — at least one finding at the threshold
- Set `--fail-on none` for informational mode; `any` for the strictest gate

For per-CI recipes including Bitbucket / Azure / Drone / Jenkins, see
[docs/ci-integration.md](./docs/ci-integration.md).

---

## Maintenance commands

### `chdora update` — refresh the incident pack

The bundled incident pack is whatever was in your binary at build time.
The community-maintained pack lives upstream and updates as new attacks
land. **Without periodic `update`, chaindora only knows about incidents
that existed when you installed the binary.**

```sh
chdora update                  # fetch the latest into ~/.chaindora/incidents
chdora update --dry-run        # report changes without writing
chdora update --verbose
```

A daily cron (`0 9 * * * chdora update`) is the recommended setup.

### `chdora upgrade` — refresh the binary

```sh
chdora upgrade                 # latest tagged release
chdora upgrade --check         # what's available
chdora upgrade --version v0.14.0
```

Verifies the SHA-256 against the published checksums file before swap.
On Windows the previous `.exe` is parked as `.exe.old` (Windows doesn't
overwrite running executables).

---

## Supported ecosystems

42 package managers across 20+ language ecosystems are gated at install
time. **Gate** means chaindora resolves the full transitive tree, runs
the checker stack, and refuses installs that fail policy. **OSV** means
the OSV.dev vulnerability database is queried for that ecosystem.

### Tier 1 — gated with full integrity coverage

These have lockfile-side content hashes used directly for the
republish-guard. Vulnerability data flows through OSV.

| Ecosystem | Package managers | OSV |
|---|---|:---:|
| npm | `npm`, `yarn` (classic + Berry), `pnpm`, `bun`, `deno` | yes |
| PyPI | `pip`, `poetry`, `uv`, `pipenv`, `pdm` | yes |
| Java / JVM | `mvn`, `gradle`, `sbt` | yes (Maven) |
| .NET | `dotnet` (NuGet), `paket` | yes (NuGet) |
| Ruby | `bundle`, `gem` | yes |
| PHP | `composer` | yes (Packagist) |
| Rust | `cargo` | yes |
| Go | `go` modules | yes |
| Mobile (Apple) | `pod` (CocoaPods), `swift` (SPM), `carthage` | yes (SwiftURL) |
| Dart/Flutter | `dart`, `flutter` | yes (Pub) |
| Elixir/Erlang | `mix` (Hex), `rebar3` | yes (Hex) |
| Haskell | `stack`, `cabal` | yes (Hackage) |
| R | `R`, `Rscript` (renv) | yes (CRAN) |

### Tier 2 — gated; integrity via registry fetch

Lockfile doesn't carry hashes; chaindora fetches from the registry.

| Ecosystem | Package managers | Integrity source |
|---|---|---|
| Bundler | `bundle add`, `bundle update` | rubygems.org API `sha` |
| Maven / Gradle / sbt | (above) | repo1.maven.org `.jar.sha1` |
| Homebrew | `brew install`, `upgrade`, `reinstall` | `brew info --json=v2` |

### Tier 3 — gated; no OSV coverage but signal from cooldown / republish-guard / static-pattern

| Ecosystem | Package managers |
|---|---|
| Conda | `conda`, `mamba`, `micromamba` |
| C/C++ | `conan`, `vcpkg` |
| OCaml | `opam` |
| Julia | `julia` (Pkg.jl, Manifest.toml) |
| Perl | `cpanm` |
| Lua | `luarocks` |
| Niche | `elm`, `nimble` (Nim), `shards` (Crystal), `zig` |

### Detection only (no registry boundary)

| Ecosystem | Manifests recognized |
|---|---|
| Docker / OCI | `Dockerfile`, `docker-compose.yml`, CI YAML `image:` |
| GitHub Actions / Gitea Actions | `.github/workflows/*.yml`, `.gitea/workflows/*.yml` |
| GitLab CI | `.gitlab-ci.yml` (`include:`) |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` (`pipe:`) |
| CircleCI Orbs | `.circleci/config.yml` (`orbs:`) |
| Azure Pipelines | `azure-pipelines.yml` (`task:`) |

OS-level package managers (apt / yum / dnf / apk / winget / chocolatey)
are **deliberately out of scope for the gate** — different threat
model, root-level install boundary, distribution maintainers do their
own vetting. Detection-side coverage (`chdora forensics --deep`)
enumerates installed system packages and matches against OSV.

Findings normalize to [Package URLs (PURLs)](https://github.com/package-url/purl-spec).

---

## Platform support

| OS | Status |
|---|---|
| Linux amd64 / arm64 | Tier 1 — full feature parity, CI-verified each release |
| macOS amd64 / arm64 | Tier 1 — full feature parity, CI-verified each release |
| Windows amd64 / arm64 | Tier 1 — cross-compiles cleanly; PowerShell-profile and Credential Manager checks; gate shims use `.cmd` form |

CI matrix runs `go test ./... -race` on all three OSes for every PR and
every release tag.

---

## Roadmap

Roadmap is driven by the [threat model](./docs/threat-model.md), not
by ecosystem checklists. Each milestone targets a specific attack-
surface gap identified there.

- **v0.10** ✅ shipped — SonarQube-grade `chdora ci` (baseline /
  suppression / PR comments); yarn + pnpm gate resolvers; PyPI gate
  parity for cooldown / OSV / static-pattern; `chdora watch` daemon;
  sigstore-provenance check.
- **v0.11** ✅ shipped — ecosystem-pluggable gate refactor;
  RubyGems + crates.io + Maven Central full-stack ecosystems;
  PyPI gate parity completed (publisher-change /
  maintainer-trust / version-diff); build-time + import-time
  static-scan patterns (Go `init()`, Rust `build.rs`); trust-
  anchor drift forensics (`.npmrc` / `pip.conf` / `git insteadOf`
  / CA store baseline + drift detection).
- **v0.11.1** ✅ shipped — git-URL trust evaluator: evaluates
  `npm install user/repo`, `pip install git+...`, CMake
  `FetchContent` style deps on host-trust + ref-pinning +
  transport scheme. Well-known host + 40-hex SHA = Approve;
  branch refs / unknown hosts / http:// = Block under strict
  policy.
- **v0.13** ✅ shipped — Server mode: `chdora server start` accepts
  findings from many `chdora agent` clients, persists them to a
  single-file JSON store, serves a fleet dashboard at `/` and a
  JSON API at `/api/v1/*`. Per-agent bearer tokens; optional
  enrollment secret. `chdora watch` auto-pushes when enrolled.
  TLS termination is bring-your-own (caddy / nginx / Cloudflare Tunnel).
  Webhook ingest, scheduled fleet scans, SAML/OIDC dashboard auth and a
  SQL backend remain on the v0.13.x backlog — not yet implemented.
- **v0.14** ✅ shipped — package-manager coverage push:
  Composer/Packagist (PHP), NuGet (.NET), Poetry / uv / Pipenv /
  PDM (Python alts), Gradle, sbt, CocoaPods + Swift PM + Carthage
  (mobile), Hex/Mix + rebar3 (Erlang/Elixir), Pub (Dart/Flutter),
  bun + deno (modern JS), conda + mamba, Homebrew, Conan, vcpkg,
  Paket (F#), stack + cabal (Haskell), opam (OCaml), renv (R),
  Pkg.jl (Julia), cpanm (Perl), luarocks, Elm, nimble, shards, zig.
  **42 package managers in total.** Hash-keyed verdict cache at
  `~/.chaindora/gate-cache/` doubles as a republish-attack detector
  (same `name@version` reappearing with different bytes → Block).
- **v0.15** — AI / ML supply chain: HuggingFace pickle scanner,
  PyTorch / TF / Keras model file scanner, MCP server / Claude
  Code skill auditor.
- **v0.16** — IaC supply chain: Terraform / OpenTofu modules +
  providers, Helm charts (deps + hooks), Ansible Galaxy.
- **v0.17** — Emerging surfaces: devcontainer feature scanner,
  slopsquatting heuristic (LLM-hallucinated typosquats), Vim /
  Neovim / JetBrains plugin-manager inventory; PlatformIO; game-
  engine asset stores — community-driven.
- **v1.0** — Reproducible-build verification: for sigstore-attested
  packages, byte-compare the published tarball against what builds
  from the attested git commit. Closes the "registry compromised
  but source clean" gap.

See [docs/threat-model.md](./docs/threat-model.md) for the full
attack-surface map, scope boundaries, and the prioritization framework
that ranks these milestones.

---

## Architecture, internals, contributing

- [docs/threat-model.md](./docs/threat-model.md) — the full attack-surface
  map: code-entry vectors, code-execution moments, trust-anchor vectors.
  Defines what chaindora covers, what's deliberately out-of-scope, and
  the prioritization framework that drives the roadmap
- [docs/architecture.md](./docs/architecture.md) — internal package layout
  and data flow
- [docs/incident-pack.md](./docs/incident-pack.md) — how to contribute new
  incident entries (the highest-leverage contribution)
- [docs/ci-integration.md](./docs/ci-integration.md) — per-CI recipes
- [CLAUDE.md](./CLAUDE.md) — on-ramp for contributors (or AI agents)
  walking into the repo cold
- [SECURITY.md](./SECURITY.md) — responsible disclosure for vulnerabilities
  in chaindora itself

The most valuable single contribution is **adding entries to the curated
incident pack** when a new supply-chain attack lands. See
[docs/incident-pack.md](./docs/incident-pack.md) for the PR flow and
quality bar.

---

## License

[Apache-2.0](./LICENSE). No CLA. No telemetry. No backdoors.
