# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--exclude <name>` flag on `scan`, `ci`, and `forensics` — comma-separated
  or repeatable directory basenames to skip during all detector walks
  (inventory, incident-pack file-artifact hunt, heuristic install-script
  walk, and project discovery). Plumbed via a new
  `inventory.WithExcludes(...)` option, `heuristic.Config{Excludes}`, and a
  variadic `incident.New(incs, excludes...)` constructor.
- Dogfood self-scan re-enabled in `.github/workflows/test.yml`: a
  separate job runs `./chaindora ci . --exclude testdata --fail-on critical,high`
  and uploads the SARIF sidecar to GitHub code-scanning. The `testdata/`
  exclusion keeps the deliberately-malicious test fixtures out of the
  results.
- `chaindora forensics --deep` — enumerates globally-installed packages
  (`npm ls -g --json` and `pip list --format=json`, with `pip3` fallback)
  and runs the full detector pipeline (OSV + incident pack + heuristics)
  against them. Skips each package manager silently if its binary isn't
  on PATH. Catches "I have a malicious npm tool installed globally that
  I'm not even using in a project" scenarios. Homebrew and apt deferred
  to a follow-up release.
- `inventory.NormalizePyPIName` is now exported so the global-pip scanner
  applies the same PEP 503 normalization the lockfile parsers do.

Future work tracked in [README's Roadmap section](./README.md#roadmap).

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
