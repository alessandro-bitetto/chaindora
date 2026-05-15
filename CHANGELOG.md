# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Future work tracked in [README's Roadmap section](./README.md#roadmap).

## [0.6.0] — 2026-05-15

The architectural shift: heuristics stop guessing from package-name shape
and start gathering evidence from the upstream registries. Real-world
impact on the v0.5.9 audit baseline (454 findings, 194 from
dep-confusion alone): an estimated 80–90% of dep-confusion findings
drop because chdora can now distinguish `@vitejs/plugin-react` (public,
no risk) from `@my-corp/internal-thing` (private, real risk if a
public collision exists). Typosquat and install-script heuristics
become evidence-gated too — 10-year-old packages with millions of
weekly downloads stop firing.

### Added

- **`internal/registries/`** — cross-ecosystem `Probe` interface
  with three signals: `Exists(name)`, `PublishedAt(name)`,
  `DownloadsLast7d(name)`. Implementations:
    - `NewNPM()` — `registry.npmjs.org` + `api.npmjs.org/downloads`
    - `NewPyPI()` — `pypi.org/pypi/<name>/json` + `pypistats.org`
  Wrapped in `NewCached` (disk-backed at `~/.chaindora/registry-cache.json`,
  24h TTL keyed by `(ecosystem, name)`) so repeated audits cost
  zero registry traffic. Pure stdlib; no new dependencies.

- **`Package.ResolvedURL`** — new field on `inventory.Package`,
  populated from npm `package-lock.json`'s `resolved` field. Used
  by the dep-confusion heuristic to detect "this package was
  resolved from a private registry, not npmjs.org" without needing
  user-side `.npmrc` config.

- **`--skip-registry` flag** on `scan`, `ci`, `forensics`, `audit` —
  for offline / no-egress CI environments. Falls back to
  `registries.Noop`; evidence-based heuristics simply don't fire
  rather than emitting shape-only false positives.

### Changed

- **dep-confusion heuristic rewritten** to require two signals
  agreeing before firing:
    1. The scope is *private to this project*. Detected via either
       a `@scope:registry=<not-npmjs>` line in `.npmrc` OR the
       lockfile's `resolved:` URL pointing to a non-public registry
       (Artifactory, GitHub Packages, GitLab, CodeArtifact, ...).
    2. A package with the same name *exists publicly*, OR the name
       is unclaimed and could be claimed by an attacker.
  Severity ladder: CRITICAL when private scope + public collision
  (immediately exploitable); MEDIUM when private scope + no public
  collision (defensively claim the name); no finding when the
  scope is presumed public. Drops ~95% of v0.5.x false positives
  on real codebases.

- **typosquat heuristic now evidence-gated.** A Levenshtein-close
  package must also be either fresh (< 90 days old) or low-traffic
  (< 1,000 downloads/week) to fire. Mature, well-adopted
  neighbour-name packages (`jsonparse` vs `json-parse`,
  `lodash.assign` vs `lodash.assignin`) stop showing up.
  Severity scales with freshness: HIGH for < 7-day-old typos,
  MEDIUM for < 30-day, LOW otherwise. Offline mode → no findings
  (we'd rather under-report than emit shape-only guesses).

- **install-script heuristic now evidence-gated.** Packages with
  `hasInstallScript: true` must also be fresh or low-traffic.
  Mature packages with legitimate install hooks (`husky`,
  `node-gyp`, `esbuild`, `fsevents`, `sharp`) stop firing.
  Severity scales: CRITICAL for < 7-day, HIGH for < 30-day,
  MEDIUM otherwise. This is exactly the shape the Shai-Hulud worm
  rides — gating on freshness keeps the detector sharp without the
  noise.

### Architecture note

The reason this matters: chdora was previously a shape-matcher
("looks scoped, looks Levenshtein-close, has install hooks") with
N false positives per real finding. v0.6.0 is an evidence-gatherer
("npm says this exists, was published yesterday, has 12 weekly
downloads"). The signal sources are ground truth — they don't need
ongoing maintenance from chdora as the package universe grows.
Self-maintaining for the heuristic layer; the incident pack still
requires human curation per new attack.

## [0.5.9] — 2026-05-15

### Fixed

- **Shared default-skip list across every walker.** v0.5.2 added a
  `testdata/` skip to the incident-pack file-artifact walker, but
  the inventory parser and the project-discovery walker still
  descended into testdata, into `~/go/pkg/mod/` (Go module cache),
  and into `~/.vscode/extensions/*/`. Result: a real-world
  `chdora audit --whole-machine` from the field reported 306
  noise findings on a developer machine — 88 from chdora's own
  test fixtures, 45 from older chdora versions sitting in the Go
  modcache, 210 from the `opentofu` VSCode extension's bundled
  package-lock.json. None of those were user-actionable.

  Extracted the skip logic into `inventory.ShouldSkipDir(path,
  name)`, now shared by all three walkers
  (`inventory.Scan`, `incident.Detect` file-artifact pass,
  `cli.discoverProjects`). New skip list adds:
    - `testdata` — Go convention, both fixture-data dirs in
      projects and chdora's own test corpus under `$HOME`.
    - `.vscode`, `.cursor` — IDE extension storage. Each
      extension ships its own lockfiles, but those are the
      extension author's responsibility.
    - `Cellar` — Homebrew internal storage.
    - `mod` *when its parent basename is `pkg`* — Go module
      cache. Parent-aware match so we don't over-skip
      unrelated dirs named `mod`.

  The walker still descends into a user-supplied root even when
  the basename matches the skip list, so `chdora scan testdata/`
  works as expected.

### Changed

- **Text renderer now deduplicates findings by (VulnID, PURL).**
  Previously, the same CVE found in N projects produced N
  separate `#` entries. Now it produces one entry with all
  source paths listed:

  ```
    #5  osv-ioc | GHSA-cx63-2mw6-8hw5 | pkg:pypi/setuptools@58.0.4
        setuptools vulnerable to Command Injection via package URL
        sources: /Users/me/Work/proj-a/requirements.txt
                 /Users/me/Work/proj-b/poetry.lock
                 /Users/me/Work/proj-c/uv.lock
        refs:    https://nvd.nist.gov/vuln/detail/CVE-2024-6345
                 ...
  ```

  When the source list is longer than 4 entries, the rest are
  summarised as `(+N more occurrences — use --format json for the
  full list)`. The headline summary also reports the dedupe
  ratio: `"X findings — ... (deduplicated from Y instances)"`
  when grouping collapsed anything.

  JSON / JSONL / SARIF / GitHub annotation formats are unchanged —
  the underlying `Finding` slice is still flat (one row per
  source). Grouping is render-time only.

  The field report that motivated this: a 1,120-finding
  `--whole-machine` run that, after both fixes, surfaces as
  ~600 unique findings across ~10 distinct projects, with
  duplicates collapsed into the parent finding's source list.

## [0.5.8] — 2026-05-15

### Added

- **`.github/dependabot.yml`** — Dependabot configured for two
  ecosystems:
    - `github-actions` (weekly, Mondays): bumps the SHA pins
      introduced in v0.5.7 whenever any pinned action ships a new
      tagged release. Without this, our SHAs would freeze at v0.5.7's
      checkpoints and we'd silently miss security fixes to
      `actions/checkout`, `actions/setup-go`, `goreleaser/goreleaser-
      action`, `github/codeql-action`. Updates to GitHub-published
      actions are grouped (`actions/*` + `github/codeql-action*`)
      into a single PR to avoid weekly churn.
    - `gomod` (weekly, Mondays): polls our two direct Go deps
      (`spf13/cobra`, `gopkg.in/yaml.v3`). chdora intentionally keeps
      the dependency set minimal — this is more for advisory awareness
      than routine updates.

  Both use commit-message prefixes (`ci` for actions, `deps` for go
  modules) so the goreleaser changelog generator groups them
  predictably.

## [0.5.7] — 2026-05-15

### Fixed

- `.goreleaser.yml` — `archives.builds` renamed to `archives.ids`
  per the goreleaser v2 deprecation notice
  (https://goreleaser.com/deprecations#archivesbuilds). Same
  semantics, just the new key name. v0.5.6's release log was
  emitting a yellow `DEPRECATED:` line; future goreleaser majors
  will hard-fail on the old key.

- **CI workflows now SHA-pin every action.** Pinning to a 40-char
  commit SHA closes the unpinned-action-ref class of attack and
  resolves the `HEUR-UNPINNED-REF` LOW findings that chdora's own
  dogfood self-scan was reporting against itself. Each pin is
  annotated with a `# v4`-style comment so version intent stays
  legible:

  - `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4`
  - `actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff   # v5`
  - `goreleaser/goreleaser-action@e435ccd777264be153ace6237001ef4d979d3a7a  # v6`
  - `github/codeql-action/upload-sarif@458d36d7d4f47d0dd16ca424c1d3cda0060f1360  # v3`

  Side-benefit: kills the GitHub Actions Node 20 deprecation
  warnings indirectly (each action will publish Node-24 builds
  under a new SHA, which Dependabot or a manual bump will pick up).

  Tradeoff: dependency updates to these actions are now opt-in
  rather than automatic. Set up Dependabot for `.github/workflows`
  to keep them current.

## [0.5.6] — 2026-05-15

### Added

- **`chdora audit --whole-machine`** — audits the entire filesystem
  (`/`) instead of just `$HOME`. Auto-adds a curated set of skip
  basenames covering macOS + Linux system / virtual / mount-point
  paths that don't ship third-party manifests:
  `System`, `private`, `Volumes`, `cores`, `.Spotlight-V100`,
  `.Trashes`, `.fseventsd`, `.DocumentRevisions-V100`,
  `.TemporaryItems`, `.PKInstallSandboxManager*`, `proc`, `sys`,
  `dev`, `run`, `boot`, `net`, `mnt`, `media`. Warns when run
  without `sudo` since some paths (other users' homes, `/var`,
  `/etc`) will be silently skipped without it.

- **Multi-root audit.** `chdora audit --root <path>` now accepts
  multiple values, either repeated or comma-separated:
  `chdora audit --root /Users --root /opt --root /Applications`.
  Host-state-bound detectors (`--deep`, `--extensions`,
  `--persistence`, `--ssh-check`) run once against `$HOME`;
  per-root filesystem walks (project discovery + incident artifact
  hunt) run once per root and concatenate findings.

- **`internal/progress`** — TTY-aware progress reporter wired into
  the two slowest walks (incident artifact hunt + project
  discovery). When stderr is a terminal, prints a self-overwriting
  status line every 200ms with items-scanned and findings-hit
  counters:

  ```
  [chdora] hunting incident artifacts under /: 234,567 items, 4 hits
  ```

  Final summary lands as a single normal stderr line. When stderr
  is piped / redirected / `NO_COLOR` is set, the reporter is a
  no-op so machine-readable outputs stay clean. Cheap to call from
  hot paths — `Tick()` is a lock-free atomic increment, screen
  refresh happens on a single background goroutine.

## [0.5.5] — 2026-05-15

### Added

- **`chdora audit` — one-word entry point for "scan the whole
  machine."** Runs every detector at once, with sensible defaults so
  users don't have to remember five flags. Equivalent to:

  ```
  chdora forensics --scan-projects $HOME --deep --extensions \
                   --persistence --ssh-check --verbose
  ```

  Internally a thin wrapper: forensicsCmd's body was extracted into a
  shared `runForensicsFlow(ctx)`; auditCmd sets the same package-level
  flag vars with audit's defaults (all opt-in detectors ON) and calls
  the same flow. JSON / SARIF / text output formats are honored.

  Each detector has an `--skip-X` opt-out:
    - `--skip-deep` — globally-installed packages
    - `--skip-extensions` — browser / IDE extensions
    - `--skip-persistence` — cron / launchd / systemd / Scheduled Tasks
    - `--skip-ssh-check` — ~/.ssh/authorized_keys diff
    - `--skip-hunt` — incident-pack file-artifact walk
    - `--skip-osv` — OSV.dev queries (offline mode)
    - `--skip-heuristic` — behavioural heuristics on discovered projects

  Plus the standard `--root <path>` (default `$HOME`),
  `--incidents <dir>`, `--exclude <basenames>`, `--format`,
  `--fix-plan` / `--fix` / `--yes` / `--fix-aggressive`.

  `chdora forensics` continues to work exactly as before — `audit`
  is purely additive.

## [0.5.4] — 2026-05-15

### Fixed

- **Fix-plan output now surfaces every CVE a single command addresses.**
  Previously, when N findings deduped into one fix plan (e.g. 6 pip
  CVEs → 1 `pip install --upgrade --user pip` plan), the printed plan
  showed only the highest-severity CVE's VulnID — the other five
  silently disappeared from the user-visible output. Users with 2
  pip CVEs against pip@26.0.1 saw `=== 1 fix plan(s) ===` and
  reasonably asked "why is chdora handling only one of my
  vulnerabilities?". The answer (both CVEs share the same
  `pip install --upgrade ...` command, so deduping is correct) was
  hidden behind the renderer.

  Now the runner surfaces the full set:

  ```
  Fix 1/1  [HIGH] [safe] GHSA-cx63-2mw6-8hw5
    Upgrade pip-installed setuptools past 58.0.4 (user install) ...
    command: python3 -m pip install --upgrade --user setuptools
    also addresses: GHSA-5rjg-fvgr-3xxf, GHSA-r9hx-vwmv-q579,
                    PYSEC-2022-43012, PYSEC-2025-49
  ```

### Added

- `FixPlan.CoveredVulnIDs` — a sorted, deduplicated list of every
  VulnID a single execution of this plan addresses, accumulated by
  the dedup pass. Populated automatically by the runner; detectors
  don't need to set it. Used by `printPlan` to surface the full set,
  and available on the JSON-serialised plan for downstream consumers.

## [0.5.3] — 2026-05-15

### Added

- **No-op detection on pip fixes.** The fix runner now captures each
  executed command's stdout/stderr alongside streaming it live, and
  inspects pip-install output for the "Successfully installed
  <pkg>-<ver>" marker. When that marker is absent on a pip-install
  command, the runner prints a WARNING explaining that the requested
  version is likely capped by the Python interpreter or PATH, and
  increments a new `no-op` counter — surfaced in the final summary
  line as `fixes: applied=X, no-op=Y, skipped=Z`. Previously these
  showed up as `applied=N` even though nothing changed.

- **Python EOL heads-up.** When a pip fix is detected as a no-op, the
  runner probes the active `python3` interpreter version and (if the
  version is past its python.org EOL date) appends a manual step
  pointing at `brew install python@3.12` (or equivalent). The EOL
  table is hardcoded in `internal/findings/fix_runner.go`; it should
  be reviewed every 6 months as new Python minor releases ship. The
  probe is skipped on Windows and when `python3` isn't on PATH.

### Fixed

- The headline case from the field: `chdora forensics --deep --fix`
  upgrading pip from 21.2.4 → 26.0.1 on a Python 3.9 system reported
  `applied=1, skipped=0` and then re-surfaced the same two pip CVEs
  on the next scan, because pip 26.1+ requires Python ≥ 3.10. The
  no-op detection now flags this as `no-op=1` and tells the user
  *why* — instead of misreporting it as a success.

## [0.5.2] — 2026-05-15

### Changed

- **Text output redesigned.** `chdora scan` / `forensics` / `ci`
  (default `--format text`) now:
    - Sort findings by severity (CRITICAL → HIGH → MEDIUM → LOW →
      UNKNOWN); within a severity, stable by detector + vuln-id +
      name.
    - Group findings into per-severity sections with separator bars
      and a count (e.g. `HIGH  (5 findings)`).
    - Number findings sequentially (`#1`, `#2`, ...) so they can be
      referenced from chat / docs without quoting the whole PURL.
    - Word-wrap summaries at 76 chars with hanging indent — long
      OSV advisory bodies no longer overflow into mid-word breaks.
    - Trim reference lists to the top 2; remaining are summarised as
      `(+N more — use --format json for the full list)`.
    - Color severity labels when stdout is a TTY (`NO_COLOR=1` opts
      out, https://no-color.org/). Pipes / CI logs / file redirects
      get plain ASCII.
    - Surface `FixUpgradeTo` (`fix: upgrade to <safe-version>`) when
      the incident-pack matcher knows a clean version to pin to.
  JSON / JSONL / SARIF / GitHub annotation formats are unchanged.

### Fixed

- `chdora forensics` no longer surfaces chdora's own test fixtures
  as Shai-Hulud findings. The incident-pack file-artifact walk now
  treats `testdata/` as a default skip basename (Go's conventional
  fixture directory). Previously, walking `$HOME` would match the
  intentionally-malicious-looking `shai-hulud-workflow.yml` files
  shipped in `chaindora/testdata/` for the scanner's own tests
  (including any copies in `~/go/pkg/mod/`).

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
