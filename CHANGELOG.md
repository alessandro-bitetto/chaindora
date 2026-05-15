# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Future work tracked in [README's Roadmap section](./README.md#roadmap).

## [0.5.1] — 2026-05-15

### Fixed

- `chdora --version` / `chdora -v` now work. v0.5.0 shipped without
  wiring the package-level `Version` variable into cobra's
  `rootCmd.Version`, so `chdora --version` returned an unknown-flag
  error. The version is now exposed via cobra's standard `--version`
  flag and formatted as `chdora <version>`. Workaround for v0.5.0
  users: `chdora upgrade --check` prints `current: <version>, latest:
  <version>` as a side effect of comparing against the GitHub
  Releases API.

## [0.5.0] — 2026-05-15

Self-upgrade, broader fix coverage, and a near-tripled incident
catalog. The release theme: chaindora is meant to know about supply
chain attacks, so v0.5 leans hard into curated incidents.

### Added

- `chdora upgrade` — self-upgrade subcommand. Queries the GitHub
  Releases API, picks the goreleaser archive matching the current
  GOOS/GOARCH, verifies its SHA-256 against the published checksums
  file, and atomically replaces the running binary. Flags: `--check`
  (report only), `--dry-run` (download + verify but skip the swap),
  `--force` (re-install same version or override the package-manager
  guard), `--version vX.Y.Z` (pin to a specific tag), `--api-url`
  (override for forks or testing), `--verbose`. On Windows the
  previous `.exe` is parked as `chdora.exe.old` because Windows
  refuses to overwrite a running executable. Refuses to act when the
  binary path looks Homebrew-/snap-managed unless `--force`.

- Incident-pack schema gains two optional fields:
    - `packages[].safe_version: "X.Y.Z"` — when set, the fix layer
      emits an upgrade command (`npm install pkg@<safe>`,
      `python3 -m pip install --upgrade pkg==<safe>`,
      `brew upgrade pkg`) instead of a bare uninstall. Drives
      upgrade-path remediation for the new incidents.
    - `post_compromise:` top-level list of strings — incident-specific
      manual steps (e.g. "rotate the npm token in ~/.npmrc"). Surfaced
      as ManualSteps on every plan emitted by the incident; the fix
      runner never auto-applies them. Both fields are also threaded
      through `findings.Finding` as `fix_upgrade_to` and
      `post_compromise` so the JSON/SARIF reports carry the same hints.

- Wildcard `versions: ["*"]` in incident YAMLs — matches any version of
  the named package. Use only for pure-malware namespaces (typosquats,
  dependency-confusion packages); the existing exact-version match path
  is unchanged for legitimate packages where only some versions were
  compromised.

- 9 new curated incidents (incident pack now ships 14 entries):
    - **npm — event-stream / flatmap-stream (Nov 2018)**: Bitcoin
      wallet stealer targeting Copay desktop bundle.
    - **npm — eslint-scope (July 2018)**: npm-token exfiltration via
      maintainer account takeover.
    - **npm — colors.js + faker.js (Jan 2022)**: maintainer
      self-sabotage; infinite Zalgo loop / emptied package.
    - **npm — node-ipc / peacenotwar (March 2022)**: geo-targeted
      file wiper (CVE-2022-23812).
    - **npm — @lottiefiles/lottie-player (Oct 2024)**: in-page Web3
      wallet drainer via compromised maintainer credentials.
    - **PyPI — python3-dateutil + jeIlyfish (Dec 2019)**: typosquat
      pair stealing SSH / GnuPG / cloud creds.
    - **PyPI — torchtriton (Dec 2022)**: dependency-confusion
      exfiltration during PyTorch nightly install window.
    - **PyPI — ultralytics (Dec 2024)**: GH-Actions injection
      delivering token stealer + XMRig cryptominer.
    - **Homebrew/Debian — xz-utils CVE-2024-3094 (March 2024)**:
      Jia Tan sshd backdoor via liblzma ifunc resolver hook.

### Changed

- **CLI binary renamed `chaindora` → `chdora`** (project name unchanged).
  The repo (`alessandro-bitetto/chaindora`), Go module path
  (`github.com/alessandro-bitetto/chaindora`), release archive prefix
  (`chaindora_<ver>_<os>_<arch>`), and data directory (`~/.chaindora/`)
  all still use `chaindora` — only the executable invocation is now
  shorter. `go install
  github.com/alessandro-bitetto/chaindora/cmd/chdora@latest` produces
  a `chdora` binary; release archives also contain `chdora` inside.
  Breaking: anyone who installed v0.4 has a `chaindora` binary that
  must be replaced (no v0.4 binary shipped `upgrade`, so there is no
  silently-broken upgrade path).

- `incident/fix.go` — package matches with a known `safe_version` now
  emit an upgrade command per ecosystem (npm/pip/brew) at
  `FixSemiSafe` instead of the bare uninstall fallback. Uninstall
  remains the fallback when no `safe_version` is declared (and is
  required for "*"-wildcard malware namespaces). Homebrew matches
  emit `brew upgrade <pkg>` and surface the target version as a
  verification step.
- `incident.normalizeEcosystem` now accepts `Homebrew`/`brew`,
  `Debian`/`deb`, `Browser Extension`/`browserext`,
  `IDE Extension`/`ideext`, and `Go`/`golang`/`Go modules` —
  previously only npm / PyPI / GitHub Actions were normalized, so
  YAMLs targeting other ecosystems silently mismatched the
  inventory's canonical ecosystem strings.

## [0.4.0] — 2026-05-15

Broader fix coverage, audit-then-apply workflow, Go modules, first
browser-extension incident, and a fix for a real OSV API rejection.

### Added

- `--fix-aggressive` flag on `scan`, `ci`, and `forensics`. When
  combined with `--fix --yes`, expands the auto-applied set to include
  `FixSemiSafe` plans (project-lockfile upgrades, package uninstalls).
  Default `--yes` stays at `FixSafe` only.
- `osvioc.PlanFix` now emits executable upgrade commands for project
  lockfile findings instead of always falling back to manual:
    - `package-lock.json` → `npm install <pkg>@latest`
    - `yarn.lock`         → `yarn upgrade <pkg> --latest`
    - `pnpm-lock.yaml`    → `pnpm update --latest <pkg>`
    - `poetry.lock`       → `poetry update <pkg>`
    - `uv.lock`           → `uv lock --upgrade-package <pkg>`
    - `Pipfile.lock`      → `pipenv update <pkg>`
    - `requirements.txt`  → manual steps (can't safely line-edit a pin
      without parsing extras / hash specs)
  Each emits a "review the resulting lockfile diff before committing"
  step. Marked `FixSemiSafe` — auto-applied only under `--fix-aggressive`.
- `chdora fix --from <file>` — new top-level subcommand. Reads
  findings from a JSON file (output of `--format json`) and runs the
  same per-detector fix pipeline without rescanning. Useful for CI
  workflows that scan-then-apply across separate steps. Flags:
  `--from <path>` (required), `--plan`, `--yes`, `--aggressive`.
- `internal/inventory/gomod.go` — parses `go.mod` for require entries
  (single-line and grouped blocks, `// indirect` annotations preserved).
  New `EcosystemGoModules` constant; OSV ecosystem mapping to "Go";
  PURL type `golang` with segment-preserving paths
  (`pkg:golang/github.com/spf13/cobra@v1.10.2`).
- First browser-extension incident pack entry:
  `incidents/great-suspender-2021.yaml` — Chrome extension
  `klbibkeccnjlkjkiokjodocebajanakg` (The Great Suspender; post-sale
  ad-injection / telemetry; removed by Google February 2021).

### Fixed

- OSV API rejection for Docker images: the bare `OCI` ecosystem name
  isn't accepted by the public query endpoint. Removed the
  `EcosystemDocker → OCI` mapping; Docker images now flow through the
  incident pack only until a registry-aware mapping
  (`OCI:gcr.io/distroless`-style) can be wired up in v0.5.

## [0.3.0] — 2026-05-15

Per-detector remediation flow: chaindora can now describe *and* apply the
fix for many of the findings it surfaces.

### Added

- `--fix-plan` / `--fix` / `--fix --yes` on `scan`, `ci`, and
  `forensics`. `--fix-plan` describes how each finding would be
  remediated and exits 0. `--fix` prompts per finding ([a]pply /
  [s]kip / [A]pply-all-remaining / [q]uit). `--fix --yes` batch-applies
  every plan whose category is `safe`. Manual / unsafe categories
  always print instructions only and never execute.
- Four-tier `FixCategory` (safe / semi-safe / unsafe / manual). Per-
  detector `PlanFix` functions:
    - **osv-ioc** — SourcePath-aware upgrade commands for `--deep`
      findings: `npm install -g …@latest`, `python3 -m pip install
      --upgrade --user …`, `brew upgrade …`. apt findings get manual
      `sudo apt-get install --only-upgrade` instructions (FixUnsafe).
      Project-lockfile findings get manual advisory references
      (FixManual; programmatic lockfile editing is v0.3.1).
    - **incident-pack** — file-artifact matches → `rm -f --` (FixSafe);
      package matches → `npm uninstall` / `pip uninstall -y`
      (FixSemiSafe).
    - **heuristic** + **hostforensics** — manualPlanFromFinding emits
      clear remediation steps without commands. Credentials and shell
      rcs are deliberately off-limits to automation.
- Plan dedup: when multiple findings would run the same upgrade
  command (e.g. 6 different `pip` CVEs all collapse to one
  `python3 -m pip install --upgrade --user pip`), the runner collapses
  them and surfaces the highest-severity finding's justification.
- `findings.Fingerprint` is now exported (used by SARIF
  `partialFingerprints` and as the per-plan stable ID).

Full-machine forensics, broader inventory reach, and a packaged release pipeline.

### Added — Forensics
- `chdora forensics --ssh-check` — snapshots `~/.ssh/authorized_keys`
  on first run into `~/.chaindora/ssh-baseline.txt`, then on subsequent
  runs flags any new key (HIGH `HOST-SSH-KEY-ADDED`) or removed key
  (MEDIUM `HOST-SSH-KEY-REMOVED`). Hashes are SHA-256, ignoring comments
  and blank lines. Configurable baseline path via `--ssh-baseline`.
- `chdora forensics --persistence` — enumerates user-level persistence
  mechanisms (cron via `crontab -l`, launchd `~/Library/LaunchAgents/*.plist`,
  systemd user units `~/.config/systemd/user/*.service`, Windows Scheduled
  Tasks via `schtasks /Query /FO CSV`). Each entry → LOW informational;
  entries whose command matches a shellrc malware pattern → HIGH
  `HOST-PERSISTENCE-SUSPICIOUS`.
- `chdora forensics --extensions` — enumerates installed extensions from
  Chromium-based browsers (Chrome / Edge / Brave / Vivaldi / Arc) and from
  VSCode-family editors (VSCode, VSCode Server, Cursor). New
  `EcosystemBrowserExt` and `EcosystemIDEExt` constants thread through to
  the existing detector pipeline so incident-pack entries can target
  specific extension IDs.
- `chdora forensics --deep` — enumerates globally-installed packages
  via `npm ls -g --json`, `pip list --format=json` (with pip3 fallback),
  `brew list --formula --versions`, and `dpkg-query -W -f='${Package}|${Version}\n'`.
  Each package manager is silently skipped when its binary isn't on PATH.
  Runs the full detector pipeline (OSV on npm/PyPI, incident pack on all,
  heuristics where applicable) against the resulting inventory.
- `chdora forensics --scan-projects <root>` — full-machine project
  discovery. Walks the filesystem for manifests, deduplicates nested
  manifests, and runs a full scan against each discovered project root.
- Windows-equivalent host forensics: PowerShell profile scanner
  (`iex (irm/iwr …)`, `[Convert]::FromBase64String`,
  `Add-MpPreference -Exclusion`, `Set-MpPreference -DisableRealtimeMonitoring`),
  Windows Credential Manager presence check, verified cross-compile
  for `GOOS=windows GOARCH={amd64,arm64}`.

### Added — Detector / inventory plumbing
- `--exclude <name>` flag on `scan`, `ci`, and `forensics` — comma-separated
  or repeatable directory basenames to skip during all detector walks
  (inventory, incident-pack file-artifact hunt, heuristic install-script
  walk, and project discovery). Plumbed via a new
  `inventory.WithExcludes(...)` option, `heuristic.Config{Excludes}`, and a
  variadic `incident.New(incs, excludes...)` constructor.
- New ecosystems: `Homebrew`, `Debian`, `Browser Extension`, `IDE Extension`,
  with matching PURL types (`pkg:brew/...`, `pkg:deb/...`,
  `pkg:browserext/...`, `pkg:ideext/...`).
- `inventory.NormalizePyPIName` is now exported so external scanners can
  apply the same PEP 503 normalization the lockfile parsers do.

### Added — Updates & releases
- `chdora update` — refreshes the curated incident pack from the
  upstream GitHub repo into `~/.chaindora/incidents/`. Atomic per-file
  writes, YAML validation before commit, `.meta.json` provenance.
  Flags: `--source`, `--dest`, `--dry-run`, `--verbose`.
- Pre-built cross-platform binaries via goreleaser
  (`.goreleaser.yml` + `.github/workflows/release.yml`): tagged pushes
  build `linux/darwin/windows` × `amd64/arm64`, publish SHA-256
  checksums, and create a GitHub Release with verification instructions.
- Dogfood self-scan job in `.github/workflows/test.yml` runs
  `./chdora ci . --exclude testdata --fail-on critical,high` on every
  push and uploads the SARIF sidecar to GitHub code-scanning.

### Fixed
- `globMatch` in the incident detector now uses `path.Match` (forward-
  slash-only) and normalizes both pattern and rel via `filepath.ToSlash`.
  Previously `filepath.Match` on Windows treated `/` as a regular
  character and `*.txt` would match `sub/foo.txt`.
- `TestCollapseNestedRoots` rebuilt with `filepath.Join` so it passes on
  both Unix and Windows test runners.
- README `Install` section now documents the
  `$(go env GOPATH)/bin` PATH gotcha that breaks `go install …@latest`
  for users whose Go bin dir isn't already on `$PATH`.

## [0.1.0] — 2026-05-15

First public release. Four commands, nine ecosystems, four detection
layers, five output formats, three desktop platforms.

### Added — Commands
- `chdora scan [path]` — project-tree scan with full detector pipeline.
- `chdora forensics` — host-state hunt: tokens, shell rc, PowerShell
  profile, Windows Credential Manager, and incident-pack file-artifact
  hunting across `$HOME`.
- `chdora forensics --scan-projects <root>` — full-machine project
  discovery. Walks the filesystem for manifests (`package.json`,
  `requirements.txt`, `Cargo.toml`, `go.mod`, `Dockerfile`,
  `.gitlab-ci.yml`, `.circleci/`, `.azure-pipelines/`, `.github/workflows/`,
  …), deduplicates nested manifests, and runs a full scan against each
  project root alongside the host-state checks.
- `chdora ci [path]` — CI-flavored wrapper with environment autodetect
  ($GITHUB_ACTIONS / $GITLAB_CI / $CIRCLECI / $BITBUCKET_BUILD_NUMBER /
  $TF_BUILD / $DRONE / $JENKINS_HOME), `--fail-on critical,high|any|none`
  policy, and `--sarif <path>` sidecar for upload to code-scanning
  dashboards.
- `chdora update` — refreshes the curated incident pack from
  `github.com/alessandro-bitetto/chaindora` into `~/.chaindora/incidents/`.
  Atomic per-file writes, YAML validation, `.meta.json` provenance.

### Added — Detectors
- **OSV-IOC** (`internal/detectors/osvioc/`) — batches inventory packages
  to `api.osv.dev/v1/querybatch`, hydrates vulns via `/v1/vulns/{id}`,
  parses CVSS v3 vectors into qualitative severity.
- **Incident pack** (`internal/detectors/incident/`) — YAML-defined
  curated incidents with package-version matches and file-artifact globs
  (`**/` prefix supported). Seeded entries: Shai-Hulud worm (Sep 2025),
  qix chalk/debug compromise (Sep 2025), ctx PyPI hijack (May 2022),
  ua-parser-js compromise (Oct 2021).
- **Host forensics** (`internal/detectors/hostforensics/`):
  - Token files (`.npmrc`, `.pypirc`, `.docker/config.json`,
    `.aws/credentials`, `.gem/credentials`, `.cargo/credentials.toml`)
  - Shell rc patterns (curl|bash, wget|sh, eval $(base64 -d …),
    eval $(curl …), nc -l)
  - PowerShell profile patterns (iex (irm/iwr …),
    [Convert]::FromBase64String, Add-MpPreference -Exclusion,
    Set-MpPreference -DisableRealtimeMonitoring)
  - Windows Credential Manager presence check
- **Heuristics** (`internal/detectors/heuristic/`):
  - Unpinned CI refs (GH Actions, GitLab CI, Docker)
  - curl|bash / eval $(…) in CI script blocks
  - npm install scripts (root `package.json` + lockfile
    `hasInstallScript`)
  - Typosquats (Levenshtein 1-2 vs curated top-N lists)
  - Dependency confusion (`.npmrc` scope-registry awareness)
  - Fresh-popular publish dates (opt-in, registry API)

### Added — Inventory parsers
- **npm**: `package-lock.json` (v1/v2/v3), `yarn.lock` (v1 + Berry),
  `pnpm-lock.yaml`
- **PyPI**: `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`
- **CI/CD**: GitHub Actions, Gitea Actions, GitLab CI, Bitbucket
  Pipelines, CircleCI Orbs, Azure Pipelines (Drone/Woodpecker covered
  transparently via the Docker walker)
- **Docker**: `Dockerfile`, `docker-compose.yml`, every CI YAML's
  `image:` field

### Added — Output
- SARIF 2.1.0 with deduplicated rules, `security-severity` property
  for GitHub code-scanning sort/filter, stable SHA-256
  `partialFingerprints` for cross-run dedup.
- JSON-Lines streaming for log shippers.
- GitHub Actions annotations (`::error file=…,line=…::…`) with proper
  `%`/`%0A`/`%0D` escaping.

### Platform
- Linux (amd64 / arm64) — Tier 1
- macOS (amd64 / arm64) — Tier 1
- Windows (amd64 / arm64) — Tier 1 (cross-compile verified)

### CI
- GitHub Actions workflow at `.github/workflows/test.yml` runs
  `go vet` + `go test -race` + `go build` across Linux, macOS, and
  Windows on every push and pull request.

### Notes
- Released under [Apache-2.0](./LICENSE).
- Source: <https://github.com/alessandro-bitetto/chaindora>.
