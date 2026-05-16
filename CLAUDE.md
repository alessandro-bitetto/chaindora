# CLAUDE.md — chaindora

On-ramp for contributors (human or AI) walking into the repo cold. For the
user-facing story see [README.md](./README.md). For the threat model that
drives scope and roadmap decisions, see
[docs/threat-model.md](./docs/threat-model.md). For deeper coverage see
[docs/architecture.md](./docs/architecture.md),
[docs/incident-pack.md](./docs/incident-pack.md), and
[docs/ci-integration.md](./docs/ci-integration.md).

**Project name vs. binary name.** The project is `chaindora` (repo, Go
module, goreleaser archive prefix, `~/.chaindora/` data dir). The binary
is `chdora`. Use `chdora` for command invocations, `chaindora` for
project / repo / module references.

Repo: <https://github.com/alessandro-bitetto/chaindora> · Apache-2.0 ·
Latest tag in CHANGELOG.

---

## Mental model

Two modes, sharing the same finding format and the same incident pack:

| Mode | When | Where the code lives |
|---|---|---|
| **Prevention** (v0.9+) | Before install — block bad packages at the registry boundary | `internal/gate/` + `internal/cli/gate{,_exec,_shim}.go` |
| **Detection** (v0.1+) | After install — find compromise already on disk | `internal/detectors/*` + `internal/cli/{scan,forensics,audit,ci}.go` |

Detection has four commands that differ only in **what populates the
inventory**:

- `scan <path>` — walk a project tree's lockfiles/manifests/CI YAMLs
- `forensics` — walk host state (credentials, shell rc, persistence, …)
- `audit` — `forensics` + `scan` every project under $HOME
- `ci <path>` — `scan` tuned for CI gates (autodetect env, `--fail-on`,
  SARIF sidecar)

All four route findings through the same renderer and the same
fix-plan generator.

---

## Detection layers

Each detector emits `findings.Finding`. Each detector can be skipped via
`--skip-<name>`.

| Detector | Package | What it does |
|---|---|---|
| `osv-ioc` | `internal/detectors/osvioc/` | Batches inventory → `api.osv.dev/v1/querybatch`; hydrates vulns; parses CVSS v3 |
| `incident-pack` | `internal/detectors/incident/` | Matches inventory against YAMLs in `incidents/` (package versions + file artifacts) |
| `hostforensics` | `internal/detectors/hostforensics/` | Tokens, shell rc, PowerShell, ssh-diff, persistence, extensions, global packages |
| `heuristic` | `internal/detectors/heuristic/` | Unpinned CI refs, curl-pipe in CI scripts, install hooks, typosquat, dep-confusion, fresh-popular |
| `trustdrift` | `internal/detectors/trustdrift/` | `.npmrc` / `pip.conf` / `git insteadOf` / `/etc/hosts` / CA store baseline + drift |
| `integrity` | `internal/detectors/integrity/` | `go.sum` ↔ sum.golang.org, `Cargo.lock` checksum verification |

Findings get tagged with one `Category`:
`supply-chain-attack` / `dependency-cve` / `host-state` / `configuration`.
The `--exclude-<category>` flags filter at render time, not detection
time — JSON output still contains every category.

---

## Gate checkers

Each implements `gate.Checker` and runs against every node in the
resolved install tree. Per-package decision = worst Verdict across
checkers. Fail-closed: errors return `Unknown`, treated as Block by
default policy. Registered in `internal/cli/gate_stack.go`.

| Checker | Package | Verdict rule |
|---|---|---|
| `allowlist` | `internal/gate/allowlist.go` | Approve if listed in `chaindora.yml` allow; Block if denied |
| `osv-malicious` | `internal/gate/osv.go` | Block on `MAL-*`; Warn on `GHSA-*` / `CVE-*` |
| `cooldown` | `internal/gate/cooldown.go` | Block if version published less than threshold ago (default 72h) |
| `publisher-change` | `internal/gate/publisher.go` | Warn on different `_npmUser` since prior version |
| `maintainer-trust` | `internal/gate/maintainer.go` | Warn on brand-new / low-version / dormancy-gap signals |
| `provenance` | `internal/gate/provenance.go` | Per-ecosystem sigstore / sumdb / GPG / Trusted-Publishing attestation. Warn on regression; `--require-provenance` → Block on missing |
| `static-pattern` | `internal/gate/static.go` | Score-based: curl-pipe-shell, eval-of-dynamic, base64-encoded URLs, obfuscated blobs. Per-pattern dedup so a library using eval in multiple files counts once |
| `version-diff` | `internal/gate/versiondiff.go` | Scores the *delta* of static-pattern hits between requested and prior version |
| `git-url` | `internal/gate/giturl.go` | Evaluates `user/repo`, `git+...`, `FetchContent` style deps on host-tier + ref-pin + transport scheme. 40-hex SHA on well-known host = Approve; branch refs / unknown hosts / `http://` = Block |

Per-ecosystem resolvers produce the install tree: `resolve_npm.go`,
`resolve_yarn.go`, `resolve_pnpm.go`, `resolve_pip.go`, `resolve_cargo.go`,
`resolve_bundler.go`, `resolve_mvn.go`, `resolve_gomod.go`. Each shells
out to the real package manager with `--ignore-scripts` (or the
equivalent) for safe transitive resolution. Probe registration lives
in `probes.go`.

---

## Build / test / cross-compile

```sh
go build -o chdora ./cmd/chdora
go test ./... -race -count=1
go vet ./...

GOOS=windows GOARCH=amd64 go build -o /tmp/chdora.exe ./cmd/chdora
GOOS=windows GOARCH=arm64 go build -o /tmp/chdora-arm.exe ./cmd/chdora
```

CI matrix: `ubuntu-latest`, `macos-latest`, `windows-latest` — see
`.github/workflows/test.yml`. A second CI job dogfoods the binary
against the repo itself with `--exclude testdata --exclude website
--fail-on critical,high`. `website/` is excluded because the Angular
CLI build-time deps have their own CVE surface that doesn't ship with
the `chdora` binary; `testdata/` is excluded because it contains
intentional malicious fixtures (Shai-Hulud workflow, etc.).

Useful smoke tests during development:

```sh
./chdora scan testdata --skip-osv
./chdora gate check lodash@4.17.21 --lenient --explain
./chdora gate exec --dry-run npm install request@2.88.2    # 47-node tree, 4 transitive CVEs
./chdora audit --whole-machine --save-plan
./chdora ci testdata --exclude testdata --sarif /tmp/c.sarif --fail-on none
```

---

## Release flow

1. Update `CHANGELOG.md`: move `[Unreleased]` items into a new
   `[X.Y.Z] — YYYY-MM-DD` section. Keep `[Unreleased]` as a placeholder
   above it.
2. `git commit -m "vX.Y.Z: <short subject>"`
3. `git tag -a vX.Y.Z -m "vX.Y.Z — <short subject>"`
4. `git push origin main && git push origin vX.Y.Z`
5. `.github/workflows/release.yml` triggers on the tag push; goreleaser
   builds cross-platform archives + SHA-256 checksums + a GitHub Release.

One commit per tag is the convention — `git log --oneline` is the
design history.

---

## Repo layout

```
cmd/chdora/                     entry point (cobra root)
internal/
  cli/                          top-level commands + flag wiring + rendering
    {root,scan,ci,forensics,audit}.go             detection commands
    {fix,fixhelpers,plans,saveplan,preflight}.go  remediation commands
    {gate,gate_exec,gate_shim,gate_stack}.go      prevention commands (v0.9+)
    {server,agent,watch}.go                       server / fleet (v0.13+)
    {update,upgrade}.go                           maintenance commands
    {render,scanprojects,registries_helper}.go    shared helpers
  gate/                         install-time prevention (v0.9+)
    gate.go                     Verdict / Checker / Policy / Run
    {cooldown,osv,allowlist,publisher,maintainer,static,versiondiff}.go
    {provenance,giturl}.go                        v0.10 / v0.11 additions
    probes.go                                     per-ecosystem probe registration
    resolve_{npm,yarn,pnpm,pip,cargo,bundler,mvn,gomod}.go   resolvers
  fixplan/                      persistent fix plans (v0.8+)
    {fixplan,diskstore,sudo}.go DiskStore at ~/.chaindora/fix-plans/
  inventory/                    per-ecosystem lockfile / manifest parsers
    {npm,yarn,pnpm}.go                            npm family
    {pip,uv,pipfile}.go                           PyPI family
    {rubygems,cargo,maven,gomod}.go               Ruby / Rust / Java / Go
    {ghactions,gitlabci,bitbucket,circleci,azure}.go CI systems
    docker.go                                     Docker / OCI
    {inventory,skip,purl}.go                      dispatcher + skip rules + PURL builder
  osv/                          {client,cvss,semver}.go
  incidents/                    YAML loader + ResolveDir
  findings/                     Finding type + emitters + fix runner
    {finding,sarif,jsonl,ghannotations}.go
    {fix,fix_runner}.go         FixPlan + dedup + execution
  detectors/
    osvioc/                     OSV-IOC detector + PlanFix
    incident/                   incident-pack matcher + PlanFix
    hostforensics/              tokens / shellrc / powershell / wincreds / ssh /
                                persistence / extensions / globalpkgs
    heuristic/                  unpinned / cishell / installscripts /
                                typosquat / depconfusion / freshpopular /
                                poplist (top-N curated lists + Levenshtein)
    trustdrift/                 v0.11+ — .npmrc / pip.conf / git insteadOf /
                                /etc/hosts / CA store baseline + drift detection
    integrity/                  v0.13.1+ — go.sum ↔ sumdb and Cargo.lock
                                checksum verification
  server/                       v0.13+ — JSON-backed fleet store + HTTP API
    {server,store,dashboard}.go HTTP routes + persistence + HTML dashboard
  registries/                   npm + PyPI + RubyGems + crates + Maven + Go
                                HTTP probes with disk cache
  progress/                     stderr status-line for slow walks
incidents/                      curated incident YAMLs (community-maintained)
testdata/                       fixtures for parser tests + integration demos
docs/                           contributor docs
website/                        chaindora.dev — Angular 18 static site (v0.13.2+)
.github/workflows/              test.yml (matrix + dogfood) + release.yml
```

---

## Conventions

- **Go 1.22+.** Two external deps (`spf13/cobra`, `gopkg.in/yaml.v3`); add
  new ones reluctantly. `golang.org/x/term` was considered for TTY
  detection and rejected — stdlib `os.Stdin.Stat() & os.ModeCharDevice`
  works fine.
- `gofmt -s`, `go vet`, `golangci-lint` clean on every change.
- `go test ./... -race` must pass on all three OS matrix entries.
- Table-driven tests for every parser and helper. `httptest.Server` for
  anything that would hit a network in production (no live OSV in
  `go test`). Inject probes via interfaces, not concrete types.
- Path matching uses `filepath.ToSlash` + `path.Match` — **never**
  `filepath.Match` directly. On Windows the separator is `\`, so
  `filepath.Match` lets `*` cross `/`; we had a real regression caught
  by Windows CI.
- Cross-platform home dir: `os.UserHomeDir()` reads `$HOME` on Unix
  but `$USERPROFILE` on Windows. Tests that override home must
  `t.Setenv` BOTH or the Windows job will fail.
- Commit messages: subject under 70 chars; body explains **why**.
  Multi-paragraph commit bodies are fine — the commit log is the
  design history for this one-author OSS project.
- Only commit when explicitly asked. Never `git push --force` to `main`.

---

## Per-package gotchas

### `internal/gate`

- The gate fails CLOSED. Network errors / parse failures return
  `Verdict=Unknown` which the default Strict Policy treats as Block.
  Detection tools fail open; a prevention tool must fail closed. Don't
  add `Approve` returns on error.
- The npm resolver shells out to the real `npm`. Recursion guard in
  `findRealPackageManager` content-sniffs the `"chdora gate shim"`
  marker so the shim can't loop into itself even if `$HOME` shifted.
  Don't remove the sniff.
- `gate exec` uses `DisableFlagParsing: true` because npm has hundreds
  of flags that would clash with chdora's gate flags. Manual flag
  parsing in `splitGateExecArgs`: anything BEFORE the package manager
  name is a chdora flag, everything after is forwarded verbatim.
- `classifyGateArgs(pm, args)` is the one place that decides which PM
  invocations are gated. It returns `gatePassthrough` (non-install /
  non-update verbs, lockfile-restore like `npm install` alone),
  `gateProceed` (install/update with explicit packages — run the
  install-args resolver), or `gateRefuseUpdateAll` (`npm update` /
  `pnpm update` etc. with no package names — route to the update-all
  resolver if one exists, otherwise refuse).
- Two resolver families per PM in `internal/gate/`:
  - `ResolveXxxTree(ctx, pmPath, installArgs)` — install-args path.
    Spins up a temp dir with a synthetic empty manifest, runs the PM
    with the user's args in lockfile-only mode, parses the lockfile.
    Used for `npm install foo`, `npm update foo`, `cargo add serde`,
    etc.
  - `ResolveXxxUpdateAll(ctx, pmPath, cwd)` — update-all path
    (v0.13.5+). Copies the user's actual manifest + lockfile into
    a temp dir, runs the PM's update verb in lockfile-only mode,
    parses the resulting lockfile. Available for npm / pnpm /
    yarn / cargo / bundle. gem doesn't have one (no manifest;
    `gem update` walks system-wide installed gems).
- Adding a new PM means touching `classifyGateArgs` plus the per-PM
  `isXxxInstallVerb` / `isXxxUpdateVerb` predicates plus the two
  resolvers. Tests for verb classification live in
  `gate_exec_test.go`.
- `static-pattern` scores per UNIQUE pattern, not per occurrence — a
  library that legitimately uses `new Function()` in multiple files
  counts once. Without this, lodash blocks itself on its templating
  engine.

### `internal/findings`

- `Fingerprint` is **exported** because `osvioc/fix.go` and
  `incident/fix.go` use it for plan IDs. Don't rename without updating
  both consumers.
- The fix runner dedupes plans by `Command` (command-level) AND by
  `(ProjectDir, PackageName)` picking max `RequiredVersion`
  (package-level, v0.8.1). Per-finding-unique data therefore belongs
  in `ManualSteps` (not deduped), not in `Description` (highest-severity
  wins).
- `RunFixes` writes diagnostic output and command stdout to
  `opts.Output` — defaults to `os.Stderr`, never `os.Stdout`. Don't
  pollute pipe-to-jq workflows.

### `internal/fixplan`

- `DiskStore.Save` writes atomically via temp-file-plus-rename. On
  `sudo` invocations it chowns the result back to `$SUDO_USER` so
  non-sudo `chdora plans list` can read what sudo just wrote.
- Plan IDs validate against path traversal — never trust the user's
  CLI arg without `validateID`.

### `internal/detectors/osvioc`

- `osvEcosystem()` returns `""` for ecosystems OSV's public query API
  doesn't accept. Docker images were tried with `OCI` and rejected by
  the live endpoint; **deliberately disabled** until we work out the
  registry-qualified form (`OCI:gcr.io/...`). Don't reintroduce a bare
  `OCI` mapping without verifying it against the live API.
- `PlanFix` is SourcePath-driven: `"npm:global"` / `"pip:global"` /
  `"brew:global"` / `"dpkg:global"` get global-package upgrade commands;
  everything else is treated as a project-lockfile path.
- Lockfile fix plans set `ProjectDir`, `PackageName`, `RequiredVersion`
  so the package-level dedupe in `findings.DedupePlans` collapses
  N CVEs against the same package into one upgrade pinned to the max
  required version.

### `internal/detectors/incident`

- Incident YAMLs support `packages[].safe_version`. When set, the fix
  layer emits an upgrade command instead of the bare uninstall fallback.
  Pick safe_version conservatively — the last clean release for
  sabotage incidents, the post-incident clean release for credential-
  theft incidents.
- Literal `"*"` in `versions:` matches any version. Use only for
  pure-malware namespaces (typosquats, dep-confusion). Wildcard handling
  lives in the matcher in `incident.go`.
- Top-level `post_compromise:` surfaces as additional ManualSteps when
  any match fires. Use only for incident-specific guidance.

### `internal/detectors/hostforensics`

- Every add-on is gated behind a flag (`--ssh-check`, `--persistence`,
  `--extensions`, `--deep`). The default `chdora forensics` runs only
  host-state defaults (tokens / shell rc / PowerShell / wincreds) plus
  the incident-pack file-artifact hunt.
- `wincreds.scanWindowsCredentials` is `runtime.GOOS=="windows"`-gated;
  `scanCredentialDirs` is the testable helper for non-Windows hosts.

### `internal/inventory`

- Every new ecosystem needs three updates:
  1. A new `EcosystemX` constant in `inventory.go`
  2. A PURL type case in `purl.go`
  3. An `osvEcosystem` mapping (or explicit `""`) in `osvioc.go`

  Don't add a parser without all three.

---

## Don't

- Don't auto-apply credential rotation, shell rc edits, or ssh-key
  removals — those are **deliberately** `Manual` category in the fix
  runner. Adding execution there silently breaks the safety story.
- Don't add a new ecosystem without updating `osvEcosystem()`, `purl.go`,
  AND `inventory.go`'s dispatcher.
- Don't merge an incident-pack entry without at least one authoritative
  source URL in `references:`. See [docs/incident-pack.md](./docs/incident-pack.md)
  for the quality bar.
- Don't commit the `/chdora` binary (it's in `.gitignore`).
- Don't `git push --force` to `main`. Tags are immutable in published
  releases.
- Don't skip git hooks (`--no-verify`) on commits.
- Don't make gate checkers fail-open on error. Network failures return
  `Verdict=Unknown`; the policy layer decides what to do with that.

---

## Pointers

- **Threat model** — scope, attack-surface map, roadmap-prioritization
  framework: [docs/threat-model.md](./docs/threat-model.md). Start here
  when proposing a new feature: locate the attack class in the four-
  dimension space, check the scope boundary, score under the framework.
- Architecture overview: [docs/architecture.md](./docs/architecture.md)
- Incident-pack contributor guide:
  [docs/incident-pack.md](./docs/incident-pack.md)
- CI integration recipes (GitHub Actions, GitLab, CircleCI, Bitbucket,
  Azure, Jenkins, Drone): [docs/ci-integration.md](./docs/ci-integration.md)
- Per-incident schema: [incidents/SCHEMA.md](./incidents/SCHEMA.md)
- Vulnerability disclosure: [SECURITY.md](./SECURITY.md)
