---
schema_version: 2
id: 9a4d554a-d80e-4fbd-bba0-2bbace118466
name: chdora
node: cmd/chdora
category: app
---

## Purpose

`chdora` is the single static Go binary of the chaindora project: a supply-chain compromise scanner that both **prevents** bad packages at install time (the gate) and **detects** compromise already on disk (scan / forensics / audit / ci), with an optional fleet-mode HTTP server that aggregates findings from many agents. `cmd/chdora/main.go` is a one-liner that calls `cli.Execute()`; all behaviour lives under `internal/`.

## Files

| Path | Role |
|---|---|
| `cmd/chdora/main.go` | Entry point; delegates to `internal/cli.Execute` |
| `go.mod` | Module `github.com/alessandro-bitetto/chaindora`, Go 1.22, deps: `spf13/cobra`, `gopkg.in/yaml.v3` only |
| `.goreleaser.yml` | Cross-platform release build (`main: ./cmd/chdora`, binary `chdora`, CGO off, ldflags inject `cli.Version`) |
| `internal/cli/root.go` | Cobra root `chdora`, `Version` var, `ExitError`/`SilentExit`, `Execute` (maps errors to exit codes) |
| `internal/cli/scan.go`, `ci.go`, `forensics.go`, `audit.go` | The four detection commands; differ only in what fills the inventory |
| `internal/cli/scanprojects.go` | Shared project-walk used by `audit`/`forensics --scan-projects` |
| `internal/cli/render.go`, `tally.go` | Human/JSON/SARIF rendering, category filters, ANSI colours (honours `NO_COLOR`) |
| `internal/cli/fix.go`, `fixhelpers.go`, `plans.go`, `saveplan.go`, `preflight.go` | Remediation: `fix`, `plans {list,show,apply,delete,prune}`, persisted fix plans |
| `internal/cli/gate.go`, `gate_exec.go`, `gate_shim.go`, `gate_stack.go`, `gate_cache.go`, `gate_persist.go` | Prevention: `gate check`, `gate exec`, `gate install/disable/status`, `gate cache {stats,clear,path}`, checker registration |
| `internal/cli/server.go`, `agent.go`, `watch.go` | Fleet: `server start`, `agent {enroll,push,status}`, `watch` |
| `internal/cli/update.go`, `upgrade.go` | `update` (incident-pack refresh) and `upgrade` (self-update from GitHub releases) |
| `internal/gate/gate.go` | `Verdict`, `Checker`, `Policy` (`Strict`/`Lenient`), `Run`, `CachedRun`, `PackageRef`, `PackageCheck` |
| `internal/gate/cache.go` | Verdict cache at `~/.chaindora/gate-cache/` + republish-guard |
| `internal/gate/errors.go` | `PMError` / `wrapPMError`: package-manager failures vs chdora-internal errors |
| `internal/gate/allowlist.go` | `chaindora.yml` / `.chaindora.yml` / `chaindora.yaml` per-project config (`LoadConfig` walks up from cwd) |
| `internal/gate/{cooldown,osv,publisher,maintainer,provenance,static,versiondiff,giturl}.go` | The gate checkers |
| `internal/gate/probes.go`, `integrity_fetch.go` | Per-ecosystem registry probe registration; RubyGems/Maven integrity fetchers |
| `internal/gate/resolve_*.go` | ~30 install-tree resolvers covering 42 package-manager names |
| `internal/server/server.go`, `store.go`, `dashboard.go` | Fleet HTTP handler, JSON-file `Store`, HTML dashboard |
| `internal/detectors/{osvioc,incident,hostforensics,heuristic,trustdrift,integrity,predictive}/` | Detection layers, each emits `findings.Finding` |
| `internal/inventory/` | Lockfile / manifest / CI-YAML parsers (`inventory.go` dispatcher, `purl.go`, `skip.go`) |
| `internal/findings/` | `Finding` type, SARIF/JSONL/GitHub-annotation emitters, fix runner and plan dedup |
| `internal/fixplan/` | `DiskStore` at `~/.chaindora/fix-plans/` (atomic write, sudo chown-back) |
| `internal/osv/`, `internal/registries/`, `internal/incidents/`, `internal/progress/` | OSV client + CVSS/semver, registry probes with disk cache, incident YAML loader, stderr progress line |
| `incidents/*.yaml` | Curated incident pack shipped in release archives |
| `.github/workflows/test.yml`, `release.yml` | 3-OS test matrix + dogfood self-scan; on `v*` tags `release.yml` first runs `scripts/website-version.sh check` (fails the release if `website/package.json` disagrees with the tag), then goreleaser |
| `scripts/website-version.sh` | Release helper: `set vX.Y.Z` stamps the website's `package.json` + lockfile from the tag; `check vX.Y.Z` verifies them |

## Surface

**Exposes** — CLI `chdora` with commands: `scan [path]`, `ci [path]`, `forensics`, `audit`, `fix`, `plans {list,show,apply,delete,prune}`, `gate {check <pkg>@<ver>, exec <pm> <args…>, install, disable, status, cache {stats,clear,path}}`, `server start`, `agent {enroll,push,status}`, `watch`, `update`, `upgrade`, `--version`. Exit codes: 0 ok, 1 findings above `--fail-on` / gate refused, 2 generic error, or the wrapped package manager's own exit code from `gate exec`. Output formats: human text, `--format json`, SARIF sidecar (`ci --sarif`). `chdora server start` listens on `--addr` (default `:8080`, all interfaces) and serves `GET /` (HTML dashboard), `GET /healthz`, `GET /api/v1/version`, `POST /api/v1/agents/enroll`, `GET /api/v1/agents`, `GET|DELETE /api/v1/agents/{id}`, `POST /api/v1/agents/{id}/scan`, `GET /api/v1/findings`, `GET /api/v1/summary`. Go packages under `internal/` are not importable outside the module.

**Consumes** — no required env vars; it is a CLI. Optional env: `GITHUB_TOKEN` (git-url checker, GitHub API auth), `NO_COLOR` (disables ANSI), `HOME`/`USERPROFILE` via `os.UserHomeDir` (state dir `~/.chaindora/`), `GOPATH`, `PATH`, `SHELL`, `SUDO_USER`, `LOCALAPPDATA` (host forensics). External services: `api.osv.dev`, package registries (npm, PyPI, RubyGems, crates.io, Maven Central, proxy.golang.org / sum.golang.org, NuGet, Packagist, pub.dev, hex.pm, Hackage, CRAN, CocoaPods, Conda, CPAN), GitHub releases API (`upgrade`), and the real package managers on `PATH` (gate resolvers shell out with `--ignore-scripts` equivalents). Fleet agents consume `chdora server` over HTTP with `Authorization: Bearer <token>` and `X-Chaindora-Enroll-Secret` at enrollment. Per-project config file `chaindora.yml` (gate allow/deny, cooldown override, branch-ref allowance). State on disk: `~/.chaindora/{gate-cache,fix-plans,incidents,registry-cache.json,agent.json,watch-state.json,server/state.json,bin}`.

## Behavior

- **Detection pipeline**: `scan`/`ci`/`forensics`/`audit` build an `inventory` (lockfiles, manifests, CI YAMLs, host state), run the detectors (`osv-ioc`, `incident-pack`, `hostforensics`, `heuristic`, `trustdrift`, `integrity`, `predictive`), tag each finding with a `Category` (`supply-chain-attack`, `dependency-cve`, `host-state`, `configuration`, `predictive`), then render. `--exclude-<category>` filters at render time only; JSON keeps everything. `ci` adds `--fail-on` (default `critical,high`), `--baseline`/`--update-baseline`, `--suppress-file`, `--pr-comment`, SARIF output, and autodetects the CI environment. `--fix-plan`/`--fix`/`--save-plan` feed the remediation layer; `fix --plan <id>` replays a saved plan.
- **Gate (prevention)**: `gate exec <pm> <args>` parses chdora flags only before the PM name (`--lenient`, `--allow-offline`, `--skip-osv`, `--skip-static`, `--explain`, `--dry-run`, `--cooldown`), classifies the PM verb (`classifyGateArgs` → passthrough / proceed / refuse-update-all), resolves the full install tree in a temp dir via the matching `resolve_*.go`, runs `gate.CachedRun` over the checker stack from `gate_stack.go`, applies `Policy` (Strict by default: Warn and Unknown both block; `--lenient` allows Warn), and only then executes the real PM. `gate install` writes shims into `~/.chaindora/bin` and persists PATH changes; the shim recursion guard content-sniffs the `"chdora gate shim"` marker.
- **Verdict cache / republish-guard**: `CachedRun` caches Approve verdicts only, keyed on `(eco, name, version, integrity)` with 7-day TTL; a cached tuple seen again with a different integrity is a `republish-guard` Block. Empty integrity skips the cache entirely.
- **Predictive detection**: `internal/detectors/predictive` converts scan inventory to `gate.PackageRef`s and replays the behavioural checkers through the same cache; default severity medium, republish-guard critical.
- **Fleet mode**: `server start` opens `Store` on `<data-dir>/state.json` (default `~/.chaindora/server`), wraps `server.New(...).Handler()` in `http.Server` with read/write timeouts, and shuts down on SIGINT/SIGTERM. Enrollment mints a per-agent bearer token (only its hash is stored); `IngestFindingsWithSummary` also runs `recordCadenceAndCohortLocked`, emitting synthetic `fleet:republish-detected`, `fleet:publish-cadence-anomaly`, `fleet:cohort-fresh-install` findings. `agent enroll/push` and `watch` (when `~/.chaindora/agent.json` has a `ServerURL`) POST findings to the server.
- **Self-maintenance**: `update` refreshes the incident pack into `~/.chaindora/incidents`; `upgrade` downloads the latest goreleaser archive from GitHub releases.
- **Build**: `go build -o chdora ./cmd/chdora`; version injected with `-ldflags "-X github.com/alessandro-bitetto/chaindora/internal/cli.Version=vX.Y.Z"`. Tests: `go test ./... -race -count=1`, `go vet ./...`. No Dockerfile exists in the repo.

## Notes

- The gate **fails closed**: network/parse errors return `VerdictUnknown`, which Strict policy treats as Block. Never add Approve returns on error paths. Detection detectors fail open.
- `PMError` vs chdora-internal error is load-bearing: when the underlying PM exits non-zero, `gate exec` prints the PM's stderr verbatim and exits with the PM's code, unwrapped. Every resolver must go through `wrapPMError`.
- `gate exec` uses `DisableFlagParsing: true`; everything after the PM name is forwarded verbatim. Adding a PM means touching `classifyGateArgs`, the verb predicates, the resolver, `isGatedPM`, `shimManagers`, and possibly `isPMCwdOnly`.
- `static-pattern` scores per unique pattern, not per occurrence (otherwise lodash blocks itself).
- Ecosystems without lockfile integrity (bun, opam, cabal, CPAN, luarocks, Paket, Elm) skip cache and republish-guard by design.
- OS package managers (apt/yum/dnf/apk/winget/choco/scoop) are intentionally out of gate scope.
- Path matching must use `filepath.ToSlash` + `path.Match`, never `filepath.Match` (Windows regression). Tests overriding home must `t.Setenv` both `HOME` and `USERPROFILE`.
- Adding an inventory ecosystem needs three edits: constant in `inventory.go`, PURL case in `purl.go`, `osvEcosystem` mapping in the osvioc detector. Bare `OCI` OSV mapping is deliberately disabled.
- Fix runner: credential rotation, shell-rc edits, ssh-key removal are deliberately `Manual`. `RunFixes` writes to stderr, never stdout. Plans dedupe by command and by `(ProjectDir, PackageName)` max version; per-finding data belongs in `ManualSteps`.
- `findings.Fingerprint` is exported and used by the osvioc and incident fix planners; renaming it breaks both.
- The fleet server speaks plain HTTP (no TLS); intended to sit behind a TLS-terminating proxy with `--enrollment-secret` set. Open enrollment when the secret is empty.
- Dogfood CI runs `chdora ci . --exclude testdata --exclude website --fail-on critical,high`; `testdata/` holds intentionally malicious fixtures.
- Release flow: CHANGELOG section, `scripts/website-version.sh set vX.Y.Z` (stamps the website version from the tag), one commit per tag `vX.Y.Z`, tag push triggers `release.yml`, which fails closed on a website-version mismatch before goreleaser runs. Latest tag at time of writing is 0.16.2 (`CHANGELOG.md`). Do not commit the built `/chdora` binary.
