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

**Predictive** (v0.15+) is detection's third gear — it replays the
gate's behavioral checkers (cooldown, publisher-change, maintainer-
trust, version-diff, provenance, republish-guard) against already-
installed packages across **32 ecosystems** (full parity with the
v0.14 gate-side coverage). Code lives in `internal/detectors/predictive/`.
Findings flow through the same renderer; default severity is medium
so the default `--fail-on=critical,high` CI gate stays quiet.
Republish-guard escalates to critical (hard tamper signal). See
[docs/architecture.md](./docs/architecture.md) for the data flow.

**v0.16 closed the predictive-coverage gap** with nine new
`registries.VersionProbe` implementations — NuGet, Packagist,
Pub, Hex, Hackage, CRAN, CocoaPods, Conda, CPAN — wired into
`buildGateProbes()`. Cooldown / publisher-change / maintainer-
trust / version-diff now fire for .NET / PHP / Dart /
Erlang-Elixir / Haskell / R / iOS / Conda-Python / Perl, in
addition to the v0.15.x npm-PyPI-RubyGems-crates-Maven-Go six.
The v0.16 release also fixed a `priorVersion` bug that
cross-pollinated parallel LTS release lines (Angular 18.x vs
19.x, React-LTS, Babel beta/main): the picker now prefers the
most recent same-major sibling and falls back to chronological
only on true major bumps. Real impact: chaindora self-scan
dropped from 10 MEDIUM `version-diff` false positives to 0.

**Fleet behavioral signals** (v0.15+, server-side) — three checks
that fire only with `chdora server` aggregating multi-agent state:
`fleet:republish-detected` (cross-agent integrity divergence),
`fleet:publish-cadence-anomaly` (4+ versions of same package
first-seen within 24h), `fleet:cohort-fresh-install` (new agent
reports a version the rest of the fleet has had for 7+ days).
Code lives in `internal/server/store.go`'s `recordCadenceAnd
CohortLocked` — same `IngestFindings` hot path as republish
detection.

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
| `integrity` | `internal/detectors/integrity/` | `go.sum` ↔ sum.golang.org, `Cargo.lock` checksum verification, **v0.15: lockfile-vs-disk** for npm/yarn/pnpm (`package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` vs `node_modules/<pkg>/package.json` — critical), plus cargo (`~/.cargo/registry/`), go (`$GOPATH/pkg/mod/`), and pip (`.venv/lib/python*/site-packages/`) drift checks at medium severity |
| `predictive` | `internal/detectors/predictive/` | v0.15+. Replays gate checkers (cooldown, publisher-change, maintainer-trust, version-diff, provenance) against the scan inventory. Republish-guard via `~/.chaindora/gate-cache/` fires on same `name@version` reappearing with different `Integrity`. Findings default to severity medium (advisory at scan time); republish-guard escalates to critical |

Findings get tagged with one `Category`:
`supply-chain-attack` / `dependency-cve` / `host-state` /
`configuration` / `predictive` (v0.15+). The `--exclude-<category>`
flags filter at render time, not detection time — JSON output still
contains every category.

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
| `republish-guard` | `internal/gate/cache.go` (fires inside `CachedRun`) | Block when the cache already holds an entry for `(eco, name, version)` with a DIFFERENT `Integrity` than the current ref. Catches the maintainer-account-takeover republish pattern. Inactive when integrity is empty |

Per-ecosystem resolvers produce the install tree. **30 resolvers
across 42 PM names** (some share resolvers — bundle/gem, dart/flutter,
conda/mamba/micromamba, R/Rscript, etc.):

- **JS / TS** (5): `resolve_npm.go`, `resolve_yarn.go`,
  `resolve_pnpm.go`, `resolve_bun.go`, `resolve_deno.go`.
- **Python** (5): `resolve_pip.go`, `resolve_poetry.go`,
  `resolve_uv.go`, `resolve_pipenv.go`, `resolve_pdm.go`.
- **JVM** (3): `resolve_mvn.go`, `resolve_gradle.go`, `resolve_sbt.go`.
- **.NET** (2): `resolve_nuget.go`, `resolve_paket.go`.
- **Ruby** (1): `resolve_bundler.go`.
- **PHP** (1): `resolve_composer.go`.
- **Rust** (1): `resolve_cargo.go`.
- **Go** (1): `resolve_gomod.go`.
- **Mobile Apple** (3): `resolve_cocoapods.go`, `resolve_swiftpm.go`, `resolve_carthage.go`.
- **Dart** (1): `resolve_pub.go`.
- **BEAM** (2): `resolve_hex.go`, `resolve_rebar3.go`.
- **Haskell** (2): `resolve_stack.go`, `resolve_cabal.go`.
- **C/C++** (2): `resolve_conan.go`, `resolve_vcpkg.go`.
- **Conda** (1): `resolve_conda.go`.
- **macOS dev** (1): `resolve_brew.go`.
- **Long tail** (8): `resolve_opam.go`, `resolve_julia.go`,
  `resolve_renv.go`, `resolve_cpan.go`, `resolve_luarocks.go`,
  `resolve_elm.go`, `resolve_nimble.go`, `resolve_shards.go`,
  `resolve_zig.go`.

Each shells out to the real package manager with `--ignore-scripts`
(or the equivalent) for safe transitive resolution OR parses an
existing lockfile directly. Probe registration lives in `probes.go`.

**Two integrity-fetcher helpers** in `integrity_fetch.go` cover
ecosystems whose lockfile doesn't carry hashes: `enrichRubyGemsIntegrity`
hits rubygems.org's v2 API for `.sha`, and `enrichMavenIntegrity` hits
`repo1.maven.org` for `.jar.sha1` (with `.pom.sha1` fallback for
parent-pom-only entries). Bounded-pool concurrent fetch with 5 s
per-request timeout; failures degrade to empty Integrity, not gate
failure.

**Verdict cache** at `~/.chaindora/gate-cache/<ecosystem>/<key-hash>.json`.
Keyed on `(eco, name, version, integrity)`. Stores Approve verdicts
only (Warn/Block/Unknown get re-evaluated). 7-day TTL. Same-tuple
different-integrity → `republish-guard` Block. See `cache.go` for the
store; `gate_cache.go` exposes `chdora gate cache {stats,clear,path}`.

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
    gate.go                     Verdict / Checker / Policy / Run / CachedRun
    cache.go                    verdict cache (~/.chaindora/gate-cache/) + republish-guard
    errors.go                   PMError (distinguishes PM-said-no from chdora-internal)
    integrity_fetch.go          rubygems.org + Maven Central .sha1 fetchers
    {cooldown,osv,allowlist,publisher,maintainer,static,versiondiff}.go
    {provenance,giturl}.go                        v0.10 / v0.11 additions
    probes.go                                     per-ecosystem probe registration
    resolve_{npm,yarn,pnpm,pip,cargo,bundler,mvn,gomod}.go   v1 resolvers
    resolve_{nuget,composer,poetry,uv,gradle}.go            Tier 1 (v0.14)
    resolve_{cocoapods,swiftpm,pub,hex}.go                  Tier 2 (v0.14)
    resolve_{bun,conda,brew,conan,vcpkg}.go                 Tier 3-4 (v0.14)
    resolve_{pipenv,pdm,deno,stack,cabal,sbt,opam,
             rebar3,paket,julia,renv,carthage,
             cpan,luarocks,elm,nimble,shards,zig}.go        long tail (v0.14)
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
                                checksum verification + v0.15 lockfile-vs-disk
                                drift detection (`lockdrift.go` for npm,
                                `lockdrift_yarnpnpm.go` for yarn/pnpm,
                                `lockdrift_other.go` for cargo/go/pip)
    predictive/                 v0.15+ — gate-checker replay against scan
                                inventory across 32 ecosystems; emits findings
                                with severity=medium by default, critical for
                                republish-guard
  server/                       v0.13+ — JSON-backed fleet store + HTTP API
    {server,store,dashboard}.go HTTP routes + persistence + HTML dashboard
                                v0.15: store tracks PackageObservations
                                (per-tuple integrity), VersionTimeline
                                (per-(eco,name) version-first-seen list), and
                                CohortObservations (per-tuple per-agent first-
                                sighting), emitting three synthetic fleet
                                findings — republish-detected, publish-cadence-
                                anomaly, cohort-fresh-install
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

- The gate fails CLOSED on internal failures. Network errors / parse
  failures inside chdora return `Verdict=Unknown` which the default
  Strict Policy treats as Block. Detection tools fail open; a
  prevention tool must fail closed. Don't add `Approve` returns on
  error.
- **PMError vs chdora-internal error is a load-bearing distinction.**
  When the underlying PM exits non-zero (npm 404, peer-dep conflict,
  unresolvable spec, malformed lockfile), the resolver returns
  `*gate.PMError` carrying the captured output + exit code. The CLI
  layer (`asPMError` / `surfacePMError` in `gate_exec.go`) prints
  the PM's stderr verbatim and exits with the PM's code — no chdora
  wrapping. Rationale: that install was going to fail regardless of
  chdora. Don't pollute the user's view with a chdora-prefixed error
  layered over npm's own error. Use `wrapPMError(pm, command, output,
  err)` in `errors.go` from every resolver — it categorizes
  `*exec.ExitError` into PMError and leaves other failures wrapped
  normally.
- **`CachedRun` is the entry point, not `Run`.** `gate_exec.go` calls
  `gate.CachedRun(ctx, checkers, refs, cache)` with the disk-backed
  cache. CachedRun does three things per package: republish-guard
  lookup, exact-match cache lookup, and (on miss) full checker run +
  store. Plain `Run` is still the fallback for `cache == nil` and
  for the `chdora gate check` single-package path. Both use the same
  bounded worker pool (`maxConcurrentChecks = 16`).
- **Verdict cache writes only on Approve.** Warn/Block/Unknown
  verdicts deliberately don't cache — a user chasing a fix needs
  fresh signal next run, not yesterday's verdict. Empty `Integrity`
  also skips the cache entirely (no tamper detection means no entry).
- **Republish-guard semantics**: same `(eco, name, version)` cached
  with integrity X, install attempt presents integrity Y → Block
  with a `republish-guard` finding. Don't add Approve fall-throughs
  here; this is the supply-chain takeover signal. If a maintainer
  legitimately republishes (rare), the user clears the cache with
  `chdora gate cache clear`.
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
  `isXxxInstallVerb` / `isXxxUpdateVerb` predicates plus the resolver,
  plus `isGatedPM` and `shimManagers` for visibility in `gate status`
  / `gate install`. If the PM has no install-args CLI (devs edit
  manifest by hand), add it to `isPMCwdOnly` so the "no real args →
  passthrough" guard doesn't shortcut the resolution. Multi-token
  verbs (`dotnet add package`, `swift package resolve`, `dart pub add`)
  get inline-handled in `classifyGateArgs` rather than a single-verb
  predicate. Tests for verb classification live in `gate_exec_test.go`.
- `static-pattern` scores per UNIQUE pattern, not per occurrence — a
  library that legitimately uses `new Function()` in multiple files
  counts once. Without this, lodash blocks itself on its templating
  engine.
- **42 PMs share 10 checkers but only 23-ish ecosystems have
  integrity in lockfile or via fetcher**. Ecosystems without
  integrity (bun, opam, cabal, CPAN, luarocks, Paket, Elm) hit the
  gate but skip cache + republish-guard. This is deliberate — empty
  integrity means no tamper detection possible, and we'd rather not
  cache a verdict that we can't tie back to specific bytes.
- **OS-level PMs** (apt/yum/dnf/apk/winget/chocolatey/scoop) are
  intentionally out of scope for the gate. Different threat model
  (root install, distribution-signed packages, vetted by Debian /
  Red Hat / Alpine maintainers). Detection-side `forensics --deep`
  enumerates installed system packages instead.

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

### `internal/detectors/predictive` (v0.15+)

- The predictive detector is a thin shim — it converts the scan
  inventory into `gate.PackageRef`s and calls `gate.CachedRun` with
  a subset of the gate checker stack. New behavioral checks land in
  `internal/gate/` and predictive picks them up for free, same as
  the gate exec path.
- `inventoryToGateEcosystem` is the ecosystem-string mapping seam.
  When you add a new gate ecosystem AND an inventory parser for it,
  add a case here so predictive lights up for the new ecosystem too.
  Currently covers npm / pypi / rubygems / crates / maven / go.
- Severity calibration matters more than usual here. The defaults
  are intentionally medium (advisory at scan time) — republish-guard
  is the one exception (critical, hard tamper signal). Don't add new
  predictive checks at high or critical without considering whether
  they'll bypass the default `--fail-on=critical,high` CI gate users
  expect.
- The cache passed to `predictive.New` is the same
  `~/.chaindora/gate-cache/` the gate uses. Don't introduce a
  separate cache — the republish-guard signal works best when the
  same integrity dictionary is built up across both prevention and
  detection runs.

### `internal/inventory`

- Every new ecosystem needs three updates:
  1. A new `EcosystemX` constant in `inventory.go`
  2. A PURL type case in `purl.go`
  3. An `osvEcosystem` mapping (or explicit `""`) in `osvioc.go`

  Don't add a parser without all three.

- Note: many of the v0.14 ecosystems are gate-only and don't yet have
  detection-side inventory parsers. Detection-side coverage is a
  follow-up — file a separate issue per ecosystem. The OSV ecosystem
  strings used at the gate (`mapEcosystemToOSV` in `osv.go`) are
  independent of the inventory constants.

- v0.15 added `Package.Integrity`. Every new lockfile parser should
  populate it when the format carries a content hash — that's what
  drives both the predictive republish-guard at scan time and the
  v0.13 server's cross-agent republish-detection. Empty Integrity
  is fine (some lockfiles don't carry hashes); the downstream
  consumers degrade gracefully.

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
