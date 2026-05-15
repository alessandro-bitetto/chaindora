# CLAUDE.md — chaindora

Supply-chain compromise scanner. Detects known IOCs, post-compromise host
artifacts, suspicious dependencies, and rogue install-time code across npm,
pip, Go modules, six CI/CD systems, Docker images, and Chromium/VSCode-family
extensions.

Public repo: <https://github.com/alessandro-bitetto/chaindora> · License:
Apache-2.0 · Latest release: v0.5.0.

**Project name vs. binary name.** The *project* is `chaindora` (repo
name, Go module path, goreleaser archive prefix, `~/.chaindora/` data
dir). The *CLI binary* is `chdora` (renamed from `chaindora` in v0.5
for shorter invocation). When updating docs: use `chdora` for command
invocations, `chaindora` for project / repo / module references.

This file is the on-ramp for anyone (human or AI) walking into the repo cold.
For deeper coverage see [docs/architecture.md](./docs/architecture.md),
[docs/incident-pack.md](./docs/incident-pack.md), and
[docs/ci-integration.md](./docs/ci-integration.md).

## Quick orientation

Seven top-level commands:

- `chdora scan [path]` — project-tree scan; runs OSV + incident pack +
  heuristics over inventory.
- `chdora forensics` — host-state hunt: tokens, shell rc, PowerShell
  profile, ssh, persistence (`--persistence`), extensions
  (`--extensions`), `--deep` for globally-installed packages, and
  `--scan-projects <root>` to walk the filesystem for every project
  manifest under a root.
- `chdora ci [path]` — CI gate. Autodetects `$GITHUB_ACTIONS`,
  `$GITLAB_CI`, `$CIRCLECI`, `$BITBUCKET_BUILD_NUMBER`, `$TF_BUILD`,
  `$DRONE`, `$JENKINS_HOME`. Applies `--fail-on critical,high` by
  default and emits a SARIF sidecar with `--sarif <path>`.
- `chdora fix --from <findings.json>` — audit-then-apply remediation.
  Reads a previously-emitted findings JSON, runs the same fix pipeline
  `--fix` provides on the scan commands, without rescanning.
- `chdora update` — refresh the curated incident pack from
  `github.com/alessandro-bitetto/chaindora` into
  `~/.chaindora/incidents/`.
- `chdora audit` — single-word entry point for "scan everything on this
  machine." Thin wrapper around the forensics flow with every opt-in
  detector defaulted ON (`--deep`, `--extensions`, `--persistence`,
  `--ssh-check`) and `--scan-projects` pointed at `$HOME`. Each
  detector has a `--skip-X` opt-out. Internally calls the shared
  `runForensicsFlow(ctx)` helper that `forensics` also uses.
- `chdora upgrade` — self-upgrade the binary. Fetches the latest
  GitHub release archive, verifies SHA-256 against the published
  checksums file, and atomically replaces the running binary
  (`.exe.old` parking dance on Windows). Refuses when the binary
  looks Homebrew-/snap-managed unless `--force`.

Four detection layers (each can be skipped via `--skip-X`):

| Layer            | Code path                                  | What it does                                                                          |
| ---------------- | ------------------------------------------ | ------------------------------------------------------------------------------------- |
| **osv-ioc**      | `internal/detectors/osvioc/`               | Batches inventory → `api.osv.dev/v1/querybatch`; hydrates vulns; parses CVSS v3.       |
| **incident-pack**| `internal/detectors/incident/`             | Matches inventory against YAMLs in `incidents/` (package versions + file artifacts). |
| **hostforensics**| `internal/detectors/hostforensics/`        | Tokens, shell rc, PowerShell, ssh diff, persistence, extensions, global packages.    |
| **heuristic**    | `internal/detectors/heuristic/`            | Unpinned CI refs, curl-pipe in CI scripts, install hooks, typosquat, dep-confusion, fresh-popular. |

Output formats (`--format <fmt>`): `text` (default), `json`, `jsonl`,
`sarif` (GitHub code-scanning compatible), `github` (`::error` annotations).

## Build / test / cross-compile

```sh
go build -o chdora ./cmd/chdora
go test ./...
go vet ./...

GOOS=windows GOARCH=amd64 go build -o /tmp/chdora.exe ./cmd/chdora
GOOS=windows GOARCH=arm64 go build -o /tmp/chdora-arm.exe ./cmd/chdora
```

CI runs the same on `ubuntu-latest`, `macos-latest`, `windows-latest`
(see `.github/workflows/test.yml`). A second CI job dogfoods the binary
against the repo itself with `--exclude testdata --fail-on critical,high`.

## Release flow

1. Update `CHANGELOG.md`: move `[Unreleased]` items into a new
   `[0.X.0] — YYYY-MM-DD` section. Keep `[Unreleased]` as a
   placeholder above it.
2. `git commit -m "Promote [Unreleased] to [0.X.0] for tag"`
3. `git tag -a v0.X.0 -m "v0.X.0 — short subject"`
4. `git push origin main && git push origin v0.X.0`
5. `.github/workflows/release.yml` triggers on the tag push; goreleaser
   builds cross-platform archives + SHA-256 checksums + a GitHub Release.

## Repo layout

```
cmd/chdora/                 entry point (cobra root)
internal/
  cli/                         top-level commands + flag wiring + fix runner integration
    {root,scan,ci,forensics,audit,fix,update,upgrade}.go
    {render,fixhelpers,scanprojects}.go
  inventory/                   per-ecosystem lockfile / manifest parsers
    {npm,pip,yarn,pnpm,uv,pipfile,poetry}.go   (npm + PyPI)
    {ghactions,gitlabci,bitbucket,circleci,azure}.go (CI systems)
    {docker,gomod}.go          (Docker + Go modules)
    inventory.go               (Scan dispatcher + Source/Package types)
    purl.go                    (PURL builder per ecosystem)
  osv/                         {client,cvss}.go (OSV HTTP + CVSS v3)
  incidents/                   YAML loader + ResolveDir
  findings/                    Finding type + emitters + fix runner
    {finding,sarif,jsonl,ghannotations}.go
    {fix,fix_runner}.go
  detectors/
    osvioc/                    OSV-IOC detector + PlanFix
    incident/                  incident-pack matcher + PlanFix
    hostforensics/             tokens / shellrc / powershell / wincreds / ssh
                               persistence / extensions / globalpkgs
    heuristic/                 unpinned / cishell / installscripts
                               typosquat / depconfusion / freshpopular
                               poplist (top-N curated lists + Levenshtein)
incidents/                     curated incident YAMLs (14 entries today)
testdata/                      fixtures for parser tests + integration demos
docs/                          contributor docs
.github/workflows/             test.yml (matrix + dogfood) + release.yml (tag → goreleaser)
```

## Conventions

- **Go 1.22+.** Two external deps (`spf13/cobra`, `gopkg.in/yaml.v3`); add
  new ones reluctantly.
- `gofmt -s`, `go vet`, `golangci-lint` clean on every change.
- Table-driven tests for every parser and helper. `httptest.Server` for
  anything that would hit a network in production (no live OSV in
  `go test`).
- Path matching uses `filepath.ToSlash` + `path.Match` — **never**
  `filepath.Match` directly. On Windows the separator is `\`, so
  `filepath.Match` lets `*` cross `/`; we had a real regression caught
  by Windows CI. There are tests for both `globMatch` and
  `collapseNestedRoots` that exercise this.
- Commit messages: subject under 70 chars; body explains **why**. Use
  `Co-Authored-By:` when pair-programming. Multi-paragraph commit
  bodies are fine; this repo is a one-author OSS project where the
  commit log is the design history.
- Only commit when explicitly asked. Never `git push --force` to `main`.

## Per-package gotchas

### `internal/findings`

- `Fingerprint` is **exported** because `osvioc/fix.go` and
  `incident/fix.go` use it for plan IDs. Don't rename without updating
  both consumers.
- The fix runner **dedupes plans by `Command`**, picking the highest-
  severity finding's metadata to keep. Per-finding-unique data
  therefore belongs in `ManualSteps` (not deduped), not in `Description`
  (which the highest-severity wins).
- `RunFixes` writes its diagnostic output (and the stdout of executed
  commands) to `opts.Output` — defaults to `os.Stderr`, never
  `os.Stdout`, so it doesn't pollute pipe-to-jq workflows.

### `internal/detectors/osvioc`

- `osvEcosystem()` returns `""` for ecosystems OSV's public query API
  doesn't accept. Docker images were tried with `OCI` and rejected by
  the live endpoint; **deliberately disabled** until we work out the
  registry-qualified form (`OCI:gcr.io/...`). Don't reintroduce a bare
  `OCI` mapping without verifying it against the live API.
- `PlanFix` is SourcePath-driven: `"npm:global"` / `"pip:global"` /
  `"brew:global"` / `"dpkg:global"` get global-package upgrade
  commands; everything else is treated as a project-lockfile path and
  routed through `projectLockfileFix`.

### `internal/detectors/incident`

- Incident YAMLs support `packages[].safe_version` (one string per
  package). When set, the fix layer emits an upgrade command
  (`npm install pkg@<safe>`, `python3 -m pip install --upgrade
  pkg==<safe>`, `brew upgrade pkg`) instead of the bare uninstall
  fallback. Mark new entries' safe_version conservatively — pick
  the last clean release for sabotage incidents, the post-incident
  clean release for credential-theft incidents.
- The literal `"*"` in `versions:` matches any version. Use only for
  pure-malware namespaces (typosquats, dependency-confusion
  packages). The wildcard handling lives in the matcher in
  `incident.go` — `matchAny` flag short-circuits the version-set
  membership check.
- Top-level `post_compromise:` is a list of additional ManualSteps
  the fix layer surfaces when any match fires. Use only for
  incident-specific guidance — the fix runner already appends
  generic "audit credentials / verify dep tree" steps.

### `internal/detectors/hostforensics`

- Every add-on is gated behind a flag (`--ssh-check`, `--persistence`,
  `--extensions`, `--deep`). The default `chdora forensics`
  invocation runs **only** host-state defaults (tokens / shell rc /
  PowerShell / wincreds) + the incident-pack file-artifact hunt.
- `wincreds.scanWindowsCredentials` is `runtime.GOOS=="windows"`-gated;
  `scanCredentialDirs` is the testable helper for non-Windows hosts.
- The PowerShell profile scanner covers cross-platform `pwsh`
  (`~/.config/powershell/`) as well as Windows-specific paths.

### `internal/cli/forensics.go`

- `forensics --scan-projects <root>` and `--deep` both route through
  `scanProject(ctx, root, projectScanOpts{...})`. For `--deep` the
  inventory is supplied via `opts.PreInventory` instead of being
  walked from disk.

### `internal/inventory`

- Every ecosystem needs three updates: a new `EcosystemX` constant in
  `inventory.go`, a PURL type case in `purl.go`, and an `osvEcosystem`
  mapping (or explicit `""`) in `osvioc.go`. Don't add a parser
  without all three.

## Useful commands during development

```sh
# Integration smoke test (no network)
./chdora scan testdata --skip-osv

# Fix plan against pip globals (the headline --deep flow)
./chdora forensics --deep --skip-hunt --fix-plan

# Self-scan dogfood — matches the CI's self-scan job
./chdora ci . --exclude testdata --fail-on critical,high

# Refresh the local incident pack from upstream
./chdora update --verbose

# End-to-end CI/SARIF flow
./chdora ci testdata --exclude testdata --sarif /tmp/c.sarif --fail-on none
python3 -c "import json; d=json.load(open('/tmp/c.sarif')); print(d['version'], len(d['runs'][0]['results']))"
```

## Don't

- Don't auto-apply credential rotation, shell rc edits, or ssh key
  removals — those are **deliberately** Manual category in the fix
  runner. Adding execution there silently breaks the safety story.
- Don't add a new ecosystem without updating `osvEcosystem()`, `purl.go`,
  *and* `inventory.go`'s dispatcher.
- Don't merge an incident-pack entry without at least one authoritative
  source URL in `references:`. See
  [docs/incident-pack.md](./docs/incident-pack.md) for the quality bar.
- Don't commit the `/chdora` binary (it's in `.gitignore`).
- Don't `git push --force` to `main`. Tags are immutable in published
  releases.
- Don't skip git hooks (`--no-verify`) on commits.

## Pointers

- Architecture overview: [docs/architecture.md](./docs/architecture.md)
- Incident-pack contributor guide:
  [docs/incident-pack.md](./docs/incident-pack.md)
- CI integration recipes (GitHub Actions, GitLab, CircleCI, Bitbucket,
  Azure, Jenkins, Drone): [docs/ci-integration.md](./docs/ci-integration.md)
- Per-incident schema: [incidents/SCHEMA.md](./incidents/SCHEMA.md)
- Vulnerability disclosure: [SECURITY.md](./SECURITY.md)
