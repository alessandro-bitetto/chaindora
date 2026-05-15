# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Future work tracked in [README's Roadmap section](./README.md#roadmap).

## [0.2.0] — 2026-05-15

Full-machine forensics, broader inventory reach, and a packaged release pipeline.

### Added — Forensics
- `chaindora forensics --ssh-check` — snapshots `~/.ssh/authorized_keys`
  on first run into `~/.chaindora/ssh-baseline.txt`, then on subsequent
  runs flags any new key (HIGH `HOST-SSH-KEY-ADDED`) or removed key
  (MEDIUM `HOST-SSH-KEY-REMOVED`). Hashes are SHA-256, ignoring comments
  and blank lines. Configurable baseline path via `--ssh-baseline`.
- `chaindora forensics --persistence` — enumerates user-level persistence
  mechanisms (cron via `crontab -l`, launchd `~/Library/LaunchAgents/*.plist`,
  systemd user units `~/.config/systemd/user/*.service`, Windows Scheduled
  Tasks via `schtasks /Query /FO CSV`). Each entry → LOW informational;
  entries whose command matches a shellrc malware pattern → HIGH
  `HOST-PERSISTENCE-SUSPICIOUS`.
- `chaindora forensics --extensions` — enumerates installed extensions from
  Chromium-based browsers (Chrome / Edge / Brave / Vivaldi / Arc) and from
  VSCode-family editors (VSCode, VSCode Server, Cursor). New
  `EcosystemBrowserExt` and `EcosystemIDEExt` constants thread through to
  the existing detector pipeline so incident-pack entries can target
  specific extension IDs.
- `chaindora forensics --deep` — enumerates globally-installed packages
  via `npm ls -g --json`, `pip list --format=json` (with pip3 fallback),
  `brew list --formula --versions`, and `dpkg-query -W -f='${Package}|${Version}\n'`.
  Each package manager is silently skipped when its binary isn't on PATH.
  Runs the full detector pipeline (OSV on npm/PyPI, incident pack on all,
  heuristics where applicable) against the resulting inventory.
- `chaindora forensics --scan-projects <root>` — full-machine project
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
- `chaindora update` — refreshes the curated incident pack from the
  upstream GitHub repo into `~/.chaindora/incidents/`. Atomic per-file
  writes, YAML validation before commit, `.meta.json` provenance.
  Flags: `--source`, `--dest`, `--dry-run`, `--verbose`.
- Pre-built cross-platform binaries via goreleaser
  (`.goreleaser.yml` + `.github/workflows/release.yml`): tagged pushes
  build `linux/darwin/windows` × `amd64/arm64`, publish SHA-256
  checksums, and create a GitHub Release with verification instructions.
- Dogfood self-scan job in `.github/workflows/test.yml` runs
  `./chaindora ci . --exclude testdata --fail-on critical,high` on every
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
- `chaindora scan [path]` — project-tree scan with full detector pipeline.
- `chaindora forensics` — host-state hunt: tokens, shell rc, PowerShell
  profile, Windows Credential Manager, and incident-pack file-artifact
  hunting across `$HOME`.
- `chaindora forensics --scan-projects <root>` — full-machine project
  discovery. Walks the filesystem for manifests (`package.json`,
  `requirements.txt`, `Cargo.toml`, `go.mod`, `Dockerfile`,
  `.gitlab-ci.yml`, `.circleci/`, `.azure-pipelines/`, `.github/workflows/`,
  …), deduplicates nested manifests, and runs a full scan against each
  project root alongside the host-state checks.
- `chaindora ci [path]` — CI-flavored wrapper with environment autodetect
  ($GITHUB_ACTIONS / $GITLAB_CI / $CIRCLECI / $BITBUCKET_BUILD_NUMBER /
  $TF_BUILD / $DRONE / $JENKINS_HOME), `--fail-on critical,high|any|none`
  policy, and `--sarif <path>` sidecar for upload to code-scanning
  dashboards.
- `chaindora update` — refreshes the curated incident pack from
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
