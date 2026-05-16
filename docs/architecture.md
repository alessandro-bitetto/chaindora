# Architecture

How chaindora is organized and where to plug new behavior in. Companion
to [CLAUDE.md](../CLAUDE.md) (contributor on-ramp),
[docs/threat-model.md](./threat-model.md) (scope + prioritization), and
[docs/incident-pack.md](./incident-pack.md) (incident contributions).

## The two modes

chaindora has two execution modes that share findings, fix-plans, and
the incident pack, but otherwise operate independently:

| Mode | When it runs | Where the code lives |
|---|---|---|
| **Prevention** — `chdora gate` | Before bytes hit disk (intercepts `npm install`, `pip install`, etc.) | `internal/gate/` + `internal/cli/gate{,_exec,_shim,_stack}.go` |
| **Detection** — `chdora scan / audit / forensics / ci` | After packages are on disk (lockfiles, host state, CI manifests) | `internal/detectors/*` + `internal/cli/{scan,forensics,audit,ci}.go` |

Both consume `findings.Finding` objects and run through the same
remediation pipeline (`fix`, `plans`). Multi-machine fleet observability
(`chdora server`, `chdora agent`) is a separate v0.13 layer on top of
both.

## Top-level commands

Twelve commands at the cobra root:

```
chdora scan      [path]   project-tree scan
chdora audit              comprehensive single-machine sweep
chdora forensics          host-state hunt
chdora ci        [path]   CI gate (SARIF, baseline, PR comments)
chdora gate      *        install-time prevention
chdora fix       --from / --plan       apply remediation
chdora plans     list / show / apply / delete / prune
chdora watch              continuous-protection daemon
chdora update             refresh incident pack
chdora upgrade            self-upgrade with sumcheck
chdora server    *        fleet HTTP service (v0.13)
chdora agent     *        fleet client (v0.13)
```

Each command lives in its own file under `internal/cli/`. Shared
helpers (renderers, scan-projects walker, registry-probe wiring,
fix-plan integration) live alongside.

## Data flow — detection

```
                  filesystem tree
                         │
                  inventory.Scan()
                         │
                         ▼
                ┌────────────────────┐
                │     Inventory      │  Packages + Sources
                └────────┬───────────┘
                         │
   ┌──────────┬──────────┼──────────┬──────────────┬───────────┐
   ▼          ▼          ▼          ▼              ▼           ▼
 osvioc   incident   hostforen.  heuristic    trustdrift   integrity
   │          │          │          │              │           │
   └──────────┴──────────┴──────────┴──────────────┴───────────┘
                         │
                         ▼
                  findings.Finding[]
                         │
        ┌────────────────┼─────────────────┐
        ▼                ▼                 ▼
   renderText        SARIF emit        pr-comment
   (default)         (CI gates)        (markdown)
        │                │                 │
        └────────────────┼─────────────────┘
                         │
                         ▼
              optional fix-plan build
                         │
                         ▼
          ┌──────────────┼───────────────┐
          ▼              ▼               ▼
       --save-plan    --fix      end-of-run prompt
        (persist)   (execute)    (interactive)
```

## Data flow — prevention (gate)

```
   $ npm install lodash@^4
            │
            │ (intercepted by ~/.chaindora/bin/npm shim)
            ▼
   chdora gate exec npm install lodash@^4
            │
            ▼
   ┌───────────────────────────────────────────────────┐
   │  Resolve full install tree (NO code execution):   │
   │    resolve_npm / resolve_pip / resolve_nuget /    │
   │    resolve_composer / resolve_poetry / ... (30    │
   │    resolvers, 42 PM names — many share)           │
   │  → []PackageRef (eco, name, version, integrity)   │
   └────────────────┬──────────────────────────────────┘
                    │
                    ▼
   ┌───────────────────────────────────────────────────┐
   │  CachedRun(ctx, checkers, refs, cache):           │
   │    1. republish-guard: cache has same (eco,name,  │
   │       version) with DIFFERENT integrity? → Block  │
   │    2. exact-match cache hit → return cached       │
   │    3. miss → run checker stack, store Approve     │
   │                                                    │
   │  buildCheckerStack(Probes, policy):               │
   │    allowlist → osv-malicious → cooldown →         │
   │    publisher-change → maintainer-trust →          │
   │    provenance → static-pattern → version-diff →   │
   │    git-url                                         │
   │  (bounded worker pool, 16 concurrent packages)    │
   └────────────────┬──────────────────────────────────┘
                    │
                    ▼
   Per-package Decision = worst Verdict across checkers
   Whole-install Decision = worst across packages
                    │
        ┌───────────┴────────────┐
        ▼                        ▼
    Approve                  Block / Warn / Unknown
        │                        │
        ▼                        ▼
   exec real npm           refuse install, print why
```

## Data flow — server mode (v0.13+)

```
  Agent host                                Server host
  ──────────                                ───────────
  chdora agent enroll  ──POST /enroll──►  store agent
                       ◄── bearer ────

  chdora watch         ──POST /scan ────►  persist findings
   (interval / SIGHUP) ─── Bearer ────►       │
                                              ▼
                                    ┌─────────────────┐
                                    │  JSON state.json│
                                    └────────┬────────┘
                                             │
  admin browser  ◄── GET / ─────────         ▼
                     dashboard       fleet aggregates
                     /api/v1/*       (severity, agents,
                                      recent findings)
```

## Internal package layout

```
cmd/chdora/                 cobra entry point
internal/
  cli/                      top-level commands + flag wiring + rendering
    {root,scan,ci,audit,forensics}.go      detection commands
    {fix,fixhelpers,plans,saveplan,preflight}.go  remediation
    {gate,gate_exec,gate_shim,gate_stack}.go      prevention commands
    {server,agent,watch}.go                       v0.13 fleet mode
    {update,upgrade}.go                           maintenance
    {render,scanprojects,registries_helper}.go    shared helpers

  gate/                     install-time prevention (v0.9+)
    gate.go                 Verdict / Checker / Policy / Run / CachedRun
    cache.go                ~/.chaindora/gate-cache/ + republish-guard
    errors.go               PMError vs chdora-internal-error split
    integrity_fetch.go      rubygems.org + Maven Central .sha1 fetchers
    probes.go               VersionProbe + ProvenanceProbe + dispatch
    allowlist.go            chaindora.yml schema + Config + Checker
    cooldown.go             registry publish-date check
    osv.go                  OSV / MAL-* check (wraps internal/osv)
    publisher.go            cross-version publisher comparison
    maintainer.go           account-age / version-count / dormancy
    provenance.go           sigstore + ecosystem-specific attestation
    static.go               tarball download + per-language patterns
    versiondiff.go          delta scoring between bumps
    giturl.go               host-tier + ref-pin + GitHub-API enrichment
    resolve_*.go            30 per-PM resolvers covering 42 PM names:
                            npm/yarn/pnpm/bun/deno (JS), pip/poetry/uv/
                            pipenv/pdm (Python), nuget/paket (.NET),
                            composer (PHP), cargo (Rust), gomod (Go),
                            mvn/gradle/sbt (JVM), bundler (Ruby),
                            cocoapods/swiftpm/carthage (Apple),
                            pub (Dart), hex/rebar3 (BEAM),
                            stack/cabal (Haskell), conda, brew, conan,
                            vcpkg, opam, julia, renv, cpan, luarocks,
                            elm, nimble, shards, zig

  server/                   v0.13 fleet mode
    server.go               HTTP routes + auth middleware
    store.go                JSON-backed state, atomic write
    dashboard.go            embedded HTML/JS single page

  fixplan/                  persistent fix-plans (v0.8+)
    fixplan.go              Plan / Summary / AppliedResult types
    diskstore.go            ~/.chaindora/fix-plans/ DiskStore
    sudo.go                 chown-to-SUDO_USER after sudo-write

  inventory/                per-ecosystem lockfile / manifest parsers
    inventory.go            Scan dispatcher + Source/Package types
    purl.go                 PURL builder per ecosystem
    skip.go                 Shared walker-skip list
    {npm,yarn,pnpm}.go      npm family
    {pip,uv,pipfile,poetry}.go   PyPI family
    rubygems.go             Bundler Gemfile.lock
    cargo.go                Cargo.lock
    maven.go                pom.xml + property substitution
    gomod.go                go.mod
    docker.go               Dockerfile + compose
    {ghactions,gitlabci,bitbucket,circleci,azure}.go   CI systems

  registries/               registry-probe HTTP clients (cooldown +
                            tarball + provenance signal sources)
    registries.go           Probe + VersionInfo
    cache.go                disk cache at ~/.chaindora/registry-cache.json
    {npm,pypi,rubygems,crates,maven,gomod}.go         per-ecosystem probes

  osv/                      OSV.dev HTTP client + CVSS v3
    client.go               batched query + per-vuln hydration
    cvss.go                 v3 base-score calculator
    semver.go               permissive parser + MinFixedInMajor

  incidents/                YAML loader for the curated pack
    incidents.go            Incident type + Load + ResolveDir

  findings/                 unified finding shape + emitters
    finding.go              Finding + Severity + Category + Fingerprint
    fix.go                  FixPlan + categories
    fix_runner.go           dedup-by-command + dedup-by-package +
                            preflight + exec
    {sarif,jsonl,ghannotations}.go   structured-output emitters
    {suppress,baseline,prcomment}.go v0.10 CI flow helpers

  detectors/
    osvioc/                 OSV-IOC detector (uses internal/osv)
    incident/               incident-pack matcher
    hostforensics/          tokens / shellrc / powershell / wincreds /
                            ssh / persistence / extensions / globalpkgs
    heuristic/              unpinned / cishell / installscripts /
                            typosquat / depconfusion / freshpopular
    trustdrift/             v0.11 — .npmrc / pip.conf / git / CA store /
                            /etc/hosts baseline + drift
    integrity/              v0.13.1 — go.sum vs sumdb verification

  progress/                 stderr status-line for slow walks

incidents/                  curated incident YAMLs (6 entries)
testdata/                   fixtures for parser tests + integration demos
website/                    Angular site for chaindora.dev (v0.13.2+)
docs/                       contributor docs
.github/workflows/          test.yml (matrix + dogfood) + release.yml
```

## Key design invariants

### Fail-closed in prevention

Every gate checker treats failure-to-evaluate as `Verdict=Unknown`, which
Strict Policy treats as Block. Network errors, parse failures, missing
metadata — all return Unknown rather than silently approving.

A detection tool failing open ("we couldn't check, but probably fine")
is acceptable since the user is reviewing findings anyway. A prevention
tool failing open silently approves a malicious install. Two different
defaults; chaindora is in the second camp.

### Probes register once, every checker fires

`cli/gate.go`'s `buildGateProbes()` wires each registry probe to its
ecosystem key. Every checker pulls from the same `Probes` table —
adding a new ecosystem to the matrix is one-line registration, not
N×M copy-paste. The seam that made RubyGems / crates / Maven / Go
drop-in additions instead of week-long projects each.

### Findings are the universal carrier

Every detector — `osv-ioc`, `incident-pack`, `hostforensics:*`,
`heuristic:*`, `trustdrift`, `integrity` — produces the same
`findings.Finding` shape. Downstream code (SARIF emitter, fix-plan
generator, PR-comment renderer, server-ingest endpoint) doesn't care
which detector produced what. Adding a new detector category is a new
package + appending to the run loop; no changes elsewhere.

### Categories partition the output, not the detection

`findings.Category` is `supply-chain-attack` / `dependency-cve` /
`host-forensics` / `configuration`. These map to the four sections in
the text renderer and to `--exclude-<category>` flags. Detection
itself doesn't use them — every detector still runs; categories are a
render-time filter so users can focus on the surface that matters
without disabling the underlying checks.

## Cross-platform considerations

- **Windows is a Tier 1 target.** Cross-compiles cleanly. Host
  forensics has PowerShell-profile and Credential Manager paths.
  Watch out for `os.UserHomeDir()` reading `$USERPROFILE` (not
  `$HOME`) — test setups must `t.Setenv` both.
- **Path matching uses `filepath.ToSlash` + `path.Match`** —
  `filepath.Match` lets `*` cross `\` on Windows.
- **No Cgo deps.** SQLite was considered for the server store; we
  use JSON-on-disk to keep the cross-compile story clean.
- **Two external deps** (`spf13/cobra`, `gopkg.in/yaml.v3`).
  `golang.org/x/term` was rejected in favor of stdlib
  `os.Stdin.Stat() & os.ModeCharDevice`.

## Adding a new ecosystem

A complete ecosystem addition touches four packages — same pattern
every time:

1. **`internal/inventory/<name>.go`** — lockfile/manifest parser
   emitting `[]Package` with the right `Ecosystem` constant.
2. **`internal/inventory/inventory.go`** — Scan dispatcher case +
   new `EcosystemX` constant + `purl.go` PURL type mapping.
3. **`internal/registries/<name>.go`** — HTTP probe satisfying
   `gate.VersionProbe` (and optionally `gate.ProvenanceProbe`).
4. **`internal/cli/gate.go`** — register the probe in
   `buildGateProbes()`.
5. **`internal/detectors/osvioc/osvioc.go`** — add the OSV ecosystem
   string mapping (or explicit `""` if OSV doesn't cover it).

Optional, only if the ecosystem has a `gate exec` story:

6. **`internal/gate/resolve_<name>.go`** — wrap the package
   manager's "dry-run resolve" command, parse output into
   `[]PackageRef`.
7. **`internal/cli/gate_exec.go`** — switch case + verb predicate +
   shim entry.

## Per-package gotchas

Cross-referenced from CLAUDE.md, kept here for architectural context:

| Package | Critical invariant |
|---|---|
| `internal/gate/` | Fail-closed on Unknown. Recursion guard in `findRealPackageManager` content-sniffs the shim marker. `static-pattern` per-pattern dedup (so libraries that use `eval` across multiple files don't block themselves). |
| `internal/findings/` | `Fingerprint` is exported (consumed by `osvioc/fix.go` and `incident/fix.go`). `RunFixes` writes diagnostic output to `opts.Output` (default `os.Stderr`, never `os.Stdout`). |
| `internal/fixplan/` | Atomic write via temp-file + rename. Chown to `$SUDO_USER` after sudo invocations. Plan IDs validate against path traversal. |
| `internal/detectors/osvioc/` | `osvEcosystem()` returns `""` for ecosystems OSV's public API rejects. Don't reintroduce bare `OCI` mapping. |
| `internal/detectors/incident/` | `"*"` in `versions:` matches any version — use only for pure-malware namespaces. `post_compromise:` surfaces as additional ManualSteps when any match fires. |
| `internal/inventory/` | Adding an ecosystem requires updates to inventory dispatcher, `purl.go`, AND `osvioc.go`'s `osvEcosystem` mapping. |
| `internal/server/` | State writes are atomic (temp + rename). Bearer tokens stored as SHA-256 only; raw shown once at enroll. Graceful shutdown flushes state on SIGTERM. |

## Useful one-liners during development

```sh
# Integration smoke test, no network
./chdora scan testdata --skip-osv

# Gate-check one package against live OSV + cooldown
./chdora gate check lodash@4.17.21 --lenient --explain

# Full gate-exec against a real install (dry-run, doesn't actually run npm)
./chdora gate exec --dry-run npm install request@2.88.2

# Watch + auto-push to local server (single machine)
chdora server start --addr 127.0.0.1:8080 --enrollment-secret X &
chdora agent enroll --server http://127.0.0.1:8080 --enrollment-secret X
chdora watch --once

# Trust-anchor drift baseline, then drift detection
chdora forensics --trust-drift-update-baseline
# (modify .npmrc, then:)
chdora forensics
```

## Website

The chaindora.dev landing page lives at [`website/`](../website/) — a
small Angular application bootstrapped with standalone components.
Build with `cd website && npm install && ng build`; deploy the
`website/dist/` directory to any static host. See
[website/README.md](../website/README.md) for development workflow.

## Pointers

- [README.md](../README.md) — user-facing entry point
- [CLAUDE.md](../CLAUDE.md) — contributor on-ramp
- [docs/threat-model.md](./threat-model.md) — scope, attack-surface
  map, prioritization framework
- [docs/incident-pack.md](./incident-pack.md) — adding incidents
- [docs/ci-integration.md](./ci-integration.md) — per-CI recipes
- [incidents/SCHEMA.md](../incidents/SCHEMA.md) — incident YAML schema
- [SECURITY.md](../SECURITY.md) — vulnerability disclosure
