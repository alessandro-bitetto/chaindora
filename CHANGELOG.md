# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `chaindora update` — refreshes the curated incident pack from
  `github.com/alessandro-bitetto/chaindora` into `~/.chaindora/incidents/`.
  Atomic per-file writes, YAML validation before commit, `.meta.json`
  tracking last-update timestamp + source URL. Flags: `--source`,
  `--dest`, `--dry-run`, `--verbose`.

### Planned for v0.2
- Windows-equivalent host forensics: PowerShell profile scanner,
  Credential Manager check, cross-compile in CI.
- `chaindora forensics --scan-projects` — auto-discover every project
  manifest under a root and scan in parallel.
- `chaindora forensics --deep` — global packages (`npm ls -g`, pip
  system, Homebrew, apt), browser extensions, IDE extensions,
  persistence mechanisms, `~/.ssh/authorized_keys` diff.
- Static AST scan of `node_modules` / `site-packages` for install-time
  exfiltration patterns.
- Signed incident-pack tarballs and `--auto-update` opt-in on
  `scan`/`ci`.
- Pre-built binaries via `goreleaser`; Homebrew tap.
- GitHub Actions CI on the `chaindora` repo itself.

## [0.1.0] — 2026-05-15

First public release. Three commands, eight ecosystems, four detection
layers.

### Added — Commands
- `chaindora scan [path]` — project-tree scan with text / JSON / JSONL /
  SARIF / GitHub-annotation output formats.
- `chaindora forensics` — host-state hunt for leaked credentials, shell
  rc tampering, and incident-pack file artifacts across `$HOME`.
- `chaindora ci [path]` — CI-flavored wrapper with environment
  autodetect, `--fail-on` policy, and SARIF sidecar.

### Added — Detectors
- **OSV-IOC** (`internal/detectors/osvioc/`) — batches inventory
  packages to `api.osv.dev/v1/querybatch`, hydrates each vuln via
  `/v1/vulns/{id}`, parses CVSS v3 vectors into qualitative severity.
- **Incident pack** (`internal/detectors/incident/`) — YAML-defined
  curated incidents with package-version matches and file-artifact
  globs (`**/` prefix supported). Seeded entries: Shai-Hulud worm
  (Sep 2025), qix chalk/debug compromise (Sep 2025), ctx PyPI hijack
  (May 2022), ua-parser-js compromise (Oct 2021).
- **Host forensics** (`internal/detectors/hostforensics/`) — token
  files (`~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`,
  `~/.aws/credentials`, `~/.gem/credentials`, `~/.cargo/credentials.toml`),
  shell rc patterns (`curl|bash`, `wget|sh`, `eval $(base64 -d …)`,
  `eval $(curl …)`, `nc -l`).
- **Heuristics** (`internal/detectors/heuristic/`):
  - Unpinned CI refs (GH Actions, GitLab CI, Docker)
  - `curl|bash` / `eval $(…)` in CI `script:` / `run:` blocks
  - npm install scripts (root `package.json` + lockfile
    `hasInstallScript`)
  - Typosquats (Levenshtein 1-2 vs curated top-N lists)
  - Dependency confusion (`.npmrc` scope-registry awareness)
  - Fresh-popular publish dates (opt-in, registry API)

### Added — Inventory parsers
- npm: `package-lock.json` (v1/v2/v3), `yarn.lock` (v1 + Berry),
  `pnpm-lock.yaml`
- PyPI: `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`
- CI/CD: GitHub Actions, Gitea Actions, GitLab CI, Bitbucket Pipelines,
  CircleCI Orbs, Azure Pipelines (Drone/Woodpecker covered via Docker
  walker)
- Docker: `Dockerfile`, `docker-compose.yml`, every CI YAML's
  `image:` field

### Added — Output
- SARIF 2.1.0 with deduplicated rules, `security-severity` property
  for GitHub code-scanning sort/filter, stable SHA-256
  `partialFingerprints` for cross-run dedup.
- JSON-Lines streaming.
- GitHub Actions annotations (`::error file=…,line=…::…`) with proper
  `%`/`%0A`/`%0D` escaping.

### Notes
- Released under [Apache-2.0](./LICENSE).
- Source: <https://github.com/alessandro-bitetto/chaindora>.
