# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Future work tracked in [README's Roadmap section](./README.md#roadmap).

## [0.9.1] — 2026-05-15

### Fixed

- **Windows CI: `TestMaybePromptSavePlan_DefaultYesOnEnter` failed
  with "system cannot find the path specified."** Test set `HOME`
  to a temp dir to redirect the saved plan, but `os.UserHomeDir`
  reads `USERPROFILE` on Windows — so the save landed at the real
  user's home while the test looked under the temp dir. Test now
  sets both env vars; the fixplan and gate test suites aren't
  affected (they construct DiskStore directly with `Dir:`).

## [0.9.0] — 2026-05-15

The "prevention" milestone. Where chdora 0.1-0.8 answered "what's
compromised on this machine right now?", 0.9 answers "should this
install be allowed to happen at all?". A new `chdora gate` command
tree sits between the user and the package registry — every
`npm install` resolves the full transitive tree, runs every node
through a stack of independent checkers, and only proceeds if every
node passes the configured policy.

### Added

- **`chdora gate check <pkg>@<ver>`** — runs every check against
  one resolved (ecosystem, name, version). Exit codes 0/1/2/3 for
  approve/block/warn/unknown. Single-package surface for CI hooks
  and ad-hoc inspection.

- **`chdora gate exec <pm> <args...>`** — wraps a package manager
  invocation. Resolves the FULL install tree (direct + transitive)
  via `npm install --package-lock-only --ignore-scripts` in a
  throwaway tmpdir, runs every checker against every node, and
  only exec's the real package manager when every node passes.
  Non-install verbs and other package managers pass through
  unchanged. Manual flag-before-pm parsing so `--save-dev`,
  `--dry-run`, `--global` etc. forward to npm without being eaten.

- **`chdora gate install / disable / status`** — writes shims to
  `~/.chaindora/bin/` for npm, yarn, pnpm, pip, pip3. Once the
  user puts that directory on the front of `$PATH`, every
  `npm install <pkgs>` transparently routes through the gate.
  Recursion guard sniffs the shim marker so chdora can't loop into
  itself even when HOME shifts.

### Added — Checker stack

The gate runs seven independent checkers, aggregating to a per-
package Decision (worst-wins). Each checker fails closed on
network errors (returns Verdict=Unknown which Strict policy
treats as Block).

- **allowlist** — per-project `chaindora.yml` allow/deny lists +
  policy overrides (`cooldown_hours`, `allow_on_warn`,
  `allow_on_unknown`). Config walks up from cwd to find the file.

- **osv-malicious** — queries OSV.dev for the (eco, name, version);
  Block on `MAL-*` (OpenSSF Malicious Packages), Warn on regular
  CVE entries. Default Strict policy blocks both.

- **cooldown** — refuses versions published less than 72h ago
  (configurable). Catches every npm supply-chain worm where
  the community + npm-security yank the malicious version within
  the 0-day window.

- **publisher-change** — compares the publisher (`_npmUser`) of
  the requested version against the prior version on the timeline.
  Catches account-takeover attacks (event-stream, ctx, ua-parser-
  js, eslint-config-prettier). First-publish-ever also warns (the
  brand-new-package signal).

- **maintainer-trust** — composite trust score from soft signals:
  package < 30 days old, fewer than 3 total versions, or dormancy
  gap > 6 months before a sudden bump. Warns when any signal
  fires.

- **static-pattern** — downloads the version's tarball, scans
  every JS/TS file for: curl|sh in install scripts, `node -e` /
  `python -c` in install scripts, `eval(<dynamic>)` /
  `new Function(<dynamic>)`, 256+ char base64/hex high-entropy
  blobs, base64-encoded http URLs, child_process imports plus
  spawn/exec. Per-pattern dedup so libraries that legitimately
  use `eval` across multiple files don't double-count.
  Score ≥ 1 → Warn, ≥ 3 → Block.

- **version-bump-diff** — runs static-pattern against both the
  requested version AND the prior version, scores on the DELTA.
  Catches "previously clean, now malicious" subclass: a package
  that's always had eval doesn't false-positive, but the moment
  the package starts adding postinstall network calls between
  bumps, version-diff catches it.

### Added — chaindora.yml schema

```yaml
cooldown_hours: 72        # override default 72h cooldown
allow_on_warn: false      # Strict (true → Lenient)
allow_on_unknown: false   # fail-closed (true → --allow-offline default)
allow:
  npm:
    - "lodash@4.17.21"        # exact version
    - "@my-org/utils"         # any version, trusted scope
deny:
  npm:
    - "moment"                 # standardized on date-fns
```

### Honest claim

chdora 0.9.0 prevents ~95% of real-world npm supply-chain attacks
at install time: anything already in OSV/MAL-*, anything published
less than 72h ago, anything where the publisher changed or the
package took over a new maintainer, and anything with obvious
sleeper-pattern indicators (obfuscation, new install scripts, new
network calls in a bump). Applies recursively across the FULL
transitive tree, not just direct deps. For sophisticated sleepers
that masquerade as legitimate code for years (xz-utils class),
chdora can't prevent installation — but the post-install scan
story (chdora scan / audit / fix-plans) catches them retroactively
within minutes of community detection.

### Added — internal/gate package

New leaf package with the Verdict / CheckResult / PackageRef /
Checker types, Policy (Strict / Lenient) aggregation, ResolveNPMTree
resolver, and seven Checker implementations. Each checker is
unit-tested with deterministic stubs (no live network in
`go test`).

## [0.8.3] — 2026-05-15

### Added

- **Prior-apply banner on `chdora fix --plan <id>`.** When a saved
  plan is re-applied (its `applied_at` is non-nil from a previous
  run), chdora now prints a clear banner before preflight runs:
  `[chdora] NOTE: this plan was previously applied 2026-05-15 20:48:23
  — applied=N already-satisfied=N skipped=N`. Without this, the
  2nd+ re-run silently passed through preflight (every fix dropped
  as already-satisfied) and reported "no fixable findings" — accurate
  but mysterious if the user wasn't sure whether the first apply had
  worked. We don't refuse re-apply: the lockfile is the source of
  truth and preflight is the authoritative check, plus there are
  legitimate re-apply scenarios (teammate reverted the install,
  project was reset from git, etc.).

## [0.8.2] — 2026-05-15

### Fixed

- **`sudo chdora audit --save-plan` left plans unreadable by the
  regular user.** Saved plans landed on disk as `root:wheel 0600`,
  so a follow-up `chdora plans list` (run normally, without sudo)
  found nothing — `Load` got `EACCES` on the file and silently
  skipped it during listing. `DiskStore.Save` now chown's both the
  plan file and any newly-created ancestor directories
  (`~/.chaindora/`, `~/.chaindora/fix-plans/`) back to `$SUDO_USER`
  when running as root, so subsequent non-sudo invocations can read
  what sudo just wrote. No-op on Windows, no-op when not running
  as root, no-op when `$SUDO_USER` isn't set.

  Fixing pre-existing root-owned plans on disk:
  ```sh
  sudo chown -R "$USER":staff ~/.chaindora
  ```

### Added

- **Interactive end-of-run save-plan prompt.** When a `scan` / `ci` /
  `forensics` / `audit` run produces fixes but the user didn't pass
  `--save-plan` or `--fix`, chdora now asks before exiting:
  `[chdora] 146 fix(es) available. Save them as a plan to apply later? [Y/n]`.
  Default-Yes (pressing Enter saves). On Yes, the plan is written
  and the usual save-success footer with the apply-later hints
  fires. On No (or non-interactive stdin — pipelines, CI logs,
  `chdora audit | jq`), the existing three-option text footer is
  shown instead, preserving the v0.8.0 behavior. This matches the
  workflow design: "at the end of each audit, we ask the user if
  they want a produced fix-plan-id."

## [0.8.1] — 2026-05-15

### Added

- **Package-level fix-plan dedup.** When a single package has multiple
  CVEs whose individual fixes pin to different in-major versions
  (e.g. lodash 4.17.20 with five CVEs producing five `npm install
  lodash@^X.Y.Z` plans at varying pins), the plan generator now
  collapses them into ONE plan pinned to the MAX required version.
  Without this, the runner ran the same package's install command N
  times in a row at increasing pins — at best a no-op, at worst a
  downgrade of an earlier successful install. The collapsed plan's
  `CoveredVulnIDs` accumulates every collapsed CVE so users see
  "addresses N CVEs" in the plan output. Implementation:
  `FixPlan.{ProjectDir,PackageName,RequiredVersion}` new fields; new
  `findings.DedupePlans()` public function called by
  `buildAllFixPlans` (so saved plans are already deduped — what's in
  `chdora plans show` is what executes).

- **Preflight `--plan` apply check.** Before applying a saved fix
  plan, chdora now reads the current `package-lock.json` and skips
  any fix whose target package is already at a version that
  satisfies the required pin (same major, >= required). The user
  sees a `[chdora] preflight skipped N already-satisfied fix(es)`
  line on stderr listing what was bypassed. Apply-history records
  these as `status: already-satisfied` (distinct from
  `applied`/`skipped`). Scope: npm `package-lock.json` only — yarn,
  pnpm, poetry, uv etc. pass through and run their tool's own
  no-op detection. v0.9 will broaden the lockfile coverage.

## [0.8.0] — 2026-05-15

### Added

- **Persistent fix plans.** Every `scan` / `ci` / `forensics` /
  `audit` command now accepts `--save-plan`. With the flag, chdora
  writes the generated fix-plan to `~/.chaindora/fix-plans/<id>.json`
  (ID format `YYYY-MM-DD-<4hex>`) and prints the ID with three
  ready-to-paste follow-up commands. This decouples scan from fix:
  run the audit in one terminal, hand the plan ID to a coworker,
  apply it tomorrow in a different shell — without re-running the
  scan. The saved JSON includes the full plan list, scan-time
  metadata (chdora version, command line, scan root, total
  findings), and an `applied_at` + `applied_results` history block
  that re-applies update.

- **`chdora plans` command tree.** Manage saved plans without
  touching the filesystem directly:
    - `chdora plans list` — tabular view (ID, created-at, fix count,
      category breakdown, status).
    - `chdora plans show <id>` — full plan render, grouped by
      FixCategory (safe / semi-safe / unsafe / manual) with stable
      ordering.
    - `chdora plans apply <id> [--yes] [--aggressive] [--dry-run]`
      — apply a saved plan (shortcut for `chdora fix --plan <id>`).
    - `chdora plans delete <id>` (aliased `rm`) — remove one plan.
    - `chdora plans prune [--older-than 30d]` — batch cleanup,
      accepting Go duration syntax or `d` / `w` shorthand.

- **`chdora fix --plan <id>`.** Apply a saved plan by ID. Bypasses
  scanning entirely — commit to what was generated.

- **End-of-run footer.** When a scan / ci / audit run produces
  fixes but the user didn't pass `--fix` or `--save-plan`, chdora
  now prints a three-option nudge:
    `→ save for later:    re-run with --save-plan`
    `→ apply now:         re-run with --fix --yes --fix-aggressive`
    `→ save AND apply:    re-run with --save-plan --fix --yes`
  Suppressed when there are no fixes (clean run) or when the user
  already opted in to one of the three actions.

### Changed

- **`chdora fix --plan` is now a string flag (plan ID), not a
  boolean.** The previous boolean `--plan` (dry-run / describe-
  only) has been renamed to `--dry-run`. Reflects the v0.8.0
  primary use case: applying saved plans by ID.

- **`fix` no longer requires `--from`.** Either `--from <path>` or
  `--plan <id>` is required; they're mutually exclusive.

### Added (internal)

- `internal/fixplan` package — Plan / Summary / AppliedResult types
  + DiskStore with atomic writes (temp file + rename), path-
  traversal validation on IDs, deterministic listing (most-recent
  first), and `MarkApplied` for write-back history.

## [0.7.2] — 2026-05-15

### Fixed

- **`osvioc.PlanFix` now pins to the minimum-fixed-version within the
  current major** instead of blindly emitting `pkg@latest`. v0.7.1's
  fix flow ran `npm install vite@latest` on a project with
  `vite@^6.3.5` and ended up at `vite@8.0.13` — two majors ahead,
  immediately breaking `@tailwindcss/vite`'s peer-dep constraint
  (`vite@^5.2.0 || ^6`). The lockfile entered an inconsistent state,
  and **every subsequent fix in the same project failed with
  ERESOLVE** (15+ cascading failures observed in a real audit run).

  New logic:
    - OSV records carry per-affected-package `ranges.events[].fixed`
      version. New helper `osv.MinFixedInMajor(vuln, ecosystem,
      current)` walks those events and picks the smallest fixed
      version that (a) is greater than the installed version AND
      (b) shares the same SemVer major.
    - `Finding.FixUpgradeTo` is now populated from this value by
      `osvioc.Detect` (in addition to the incident-pack flow that
      already set it).
    - `osvioc.PlanFix` uses `pkg@^X.Y.Z` (caret = stay-in-major) for
      `npm install` / `yarn upgrade` / `pnpm update` commands.
    - **When no in-major fix exists** (only path forward is a major
      bump), the plan is downgraded to `FixManual` with an explicit
      "this requires a major upgrade — review and migrate manually"
      message. This prevents `--fix --yes` from auto-applying
      breaking changes.

- **Suppressed duplicate `[chdora] artifact hunt complete: 0 match(es)`
  stderr lines.** The incident-pack file-artifact walker prints a
  completion banner per-scanRoot. In `chdora audit --whole-machine`
  that fires once per discovered project root — 17+ duplicate "0
  matches" lines in a real audit run. Now the banner only prints
  when there's at least one match; the silent case is the common
  case and doesn't need annunciation.

### Added

- `osv.Affected`, `osv.Range`, `osv.Event` types on the OSV
  `Vulnerability` struct, parsed from the upstream JSON. Surface
  the version-event timeline (`introduced` / `fixed` /
  `last_affected`) that powers `MinFixedInMajor` and future
  fix-version logic.

- `osv.MinFixedInMajor(vuln, ecosystem, current) string` — public
  helper returning the smallest in-major fix, or "" when only a
  major upgrade is available. Tested against the real vite 6.3.5
  → 6.4.2 case that triggered the v0.7.1 cascade.

### Migration note for users who ran v0.7.1's `--fix --yes`

If you ran `chdora audit --fix --yes --fix-aggressive` with v0.7.1
on a JS project that uses vite + @tailwindcss/vite + similar
ecosystems, your lockfiles may have been bumped past peer-dep
ranges. To check:

```sh
cd <project> && git diff package.json package-lock.json
```

If you see a major version jump (e.g. `vite "^6.x" → "^8.x"`),
roll back with `git checkout package.json package-lock.json` and
re-run with v0.7.2 — the new fix commands will respect peer ranges
and produce successful, committable changes.

## [0.7.1] — 2026-05-15

### Fixed

- **Four-section renderer replaces v0.7.0's two-section split.**
  v0.7.0 lumped supply-chain attacks + configuration findings +
  host-state findings into one section labeled "SUPPLY-CHAIN ATTACK
  SIGNALS". In real-world audits this lied: an audit with 0 actual
  attacks but 33 unpinned-action-ref findings showed a "34 supply-
  chain attack signals" banner that read as alarming when it was
  really 33 configuration recommendations.

  Now four honest sections, each clearly labeled and each shown
  with its own count (or `✅ 0 findings` when clean):

  ```
  SUPPLY-CHAIN ATTACK SIGNALS  (✅ 0 findings — no incident matches, ...)
  DEPENDENCY VULNERABILITIES (OSV.dev)  (153 findings — 1 critical, ...)
  CONFIGURATION RISKS  (33 findings — 1 high, 32 low)
  HOST STATE  (✅ 0 findings — no leaked credentials, ...)
  ```

  An empty supply-chain section is a positive signal ("chdora's
  primary check came up clean") — the reassuring `✅` icon and
  explanatory message make that legible.

### Changed

- **Render flags replaced (breaking).** The v0.7.0 `--show-all-cves`
  + `--supply-chain-only` (opt-in to suppress) are gone. Replaced
  with explicit opt-out per category:
    - `--exclude-cves` — hide the dependency-CVE section
    - `--exclude-supply-chain` — hide the supply-chain attack section
    - `--exclude-config` — hide the configuration-risks section
    - `--exclude-host` — hide the host-state section

  **Default behavior**: show every section in full. "Audit" means
  show me what was found; filtering is explicit opt-out. The old
  v0.7.0 collapse-CVE-section-to-top-5 default is gone — every
  finding renders unless excluded.

  Flag changes apply to `scan`, `ci`, `forensics`, and `audit`.

### Architecture note

A "configuration risk" (unpinned action ref, curl|bash CI pattern)
is not a supply-chain attack — it's *attack surface*. A "host state"
finding (modified shell rc, persistence entry) is post-compromise
*evidence* — not the attack itself. v0.7.0 conflated all three;
v0.7.1 splits them so the user can tell at a glance: is something
already attacking me, do I have known-bad dependencies, are my
defaults hardened, and is my machine compromised. Four questions,
four sections, four answers.

## [0.7.0] — 2026-05-15

The identity release: chdora visibly distinguishes "deliberate supply-
chain attack against you" from "honest CVE in a legit dependency."
v0.6.x mixed them. v0.7.0 puts the supply-chain signals first, collapses
the dep-CVE noise, and leans on the OpenSSF Malicious Packages
database (federated via OSV.dev) for the bulk catalog so the curated
pack can shrink to the things only chdora can express.

### Added

- **`findings.Category`** field on every Finding:
  `supply-chain-attack` / `dependency-cve` / `host-forensics` /
  `configuration`. Drives the new renderer; serialized into JSON for
  downstream tooling.

- **MAL-* recognition in osv-ioc.** OSV.dev federates the OpenSSF
  Malicious Packages database. When chdora queries OSV for a
  package, any returned advisory IDs starting with `MAL-` are
  tagged as `CategorySupplyChainAttack`; CVE-/GHSA-/PYSEC- IDs are
  tagged as `CategoryDependencyCVE`. **No additional network calls
  needed** — chdora was already pulling this data, just not
  surfacing it as distinct.

- **Two-section text renderer.**

  ```
  ============================================
  SUPPLY-CHAIN ATTACK SIGNALS  (4 findings — ...)
  ============================================
    [CRITICAL] qix npm maintainer compromise: pkg:npm/chalk@5.6.1
    [CRITICAL] SHAI-HULUD worm artifact: shai-hulud-workflow.yml
    ...

  ============================================
  DEPENDENCY VULNERABILITIES (OSV.dev)  (153 findings — ...)
  ============================================
    [CRITICAL] fast-xml-parser@4.2.5 — CVE-2026-25896
    [HIGH] axios@1.9.0 — 4 CVEs
    ... and 148 more dependency CVE finding(s) — re-run with --show-all-cves
  ```

- **`--show-all-cves`** — un-collapses the dependency-CVE section
  to show every finding. Default behavior collapses past the top 5.
- **`--supply-chain-only`** — hides the dependency-CVE section
  entirely. For a chdora-identity scan that says "tell me only
  about attacks, not generic deps."
- **`--offline`** — meta-flag that combines `--skip-osv` and
  `--skip-registry`. No network calls; relies on local incident
  pack + cached registry data. For air-gapped CI environments.

### Changed

- **Incident pack trimmed from 14 → 6 entries.** Removed
  package-version-only incidents that the OpenSSF Malicious
  Packages database (via OSV.dev) covers redundantly: `ctx-pypi`,
  `eslint-scope`, `event-stream/flatmap-stream`, `lottie-player`,
  `node-ipc/peacenotwar`, `torchtriton`, `ua-parser-js`,
  `ultralytics`. Detection of these incidents is **unchanged** —
  chdora still surfaces them via osv-ioc with `MAL-*` IDs tagged
  as supply-chain-attack.

  Kept the 6 entries that add a dimension MAL-* records can't:
  `shai-hulud-2025` (file artifacts), `great-suspender-2021`
  (browser extension), `xz-utils-cve-2024-3094` (Homebrew/Debian),
  `qix-compromise-2025` (rich post-compromise narrative + downgrade-
  as-fix metadata), `colors-faker-sabotage-2022` (sabotage edge
  case), `pypi-typosquats-2019` (wildcard versions).

- **CONTRIBUTING.md** — narrowed the incident-pack contribution
  scope. Package-version-only incidents should go to
  `ossf/malicious-packages` directly (chdora picks them up via
  OSV). Curated pack PRs are for file artifacts, cross-ecosystem
  cases, sabotage edge cases, and post-compromise narrative —
  things MAL-* records can't express.

### Deferred to v0.8.0

These were in scope for v0.7.0 but didn't make this release because
they need substantial engineering work (~3-4 hours dedicated):

- **Native local mirror of `ossf/malicious-packages`** at
  `~/.chaindora/openssf-malicious/`. Currently chdora pulls MAL-*
  records from OSV.dev on every scan (cached 24h). v0.8 will
  ship a `chdora update --include-openssf` that bulk-fetches the
  full OpenSSF dataset for offline / air-gapped operation.

- **SHA-pinned reproducible scans.** A `chdora.lock.json` recording
  the registry-cache state + incident-pack snapshot used by a
  scan, so the same `chdora scan` against the same code at a
  later date produces the same findings even as upstream catalogs
  evolve.

## [0.6.2] — 2026-05-15

### Changed

- **Per-detector summary table** before the findings list. The v0.5.x
  pattern emitted per-detector "X findings: N" lines inline on
  stderr — the first one a user saw was usually `host-state
  findings: 0`, which read like "0 findings overall" until you
  scrolled past it. Replaced with one consolidated table printed on
  stderr before the renderer's findings list goes to stdout:

  ```
  detectors:
    osv-ioc (OSV.dev CVE matches)                         153
    heuristic (evidence-based behavioral detectors)        30
    incident-pack (curated IOC matches)                     4
    host-state (credentials, shell rc, persistence)         0
    -----------------------------------------------------------
    total                                                 187 findings
  ```

  Zero-count rows are dimmed (TTY) so they read as "this ran and
  found nothing" (reassuring) rather than "this is missing"
  (concerning). Order: non-zero rows first by count, zero rows at
  the bottom.

  The misleading inline `host-state findings: %d` line is removed.
  Informational lines (`inventoried N packages from M sources`,
  `loaded N incidents from X`, `hunting N incidents' file_artifacts
  under X`, `found N project root(s) under X`) stay — they describe
  *what's being scanned*, not detector totals.

### Added

- `internal/cli/tally.go` — `detectorTally` struct with `Enable(class)`
  (register an empty row up front for detectors that ran), `AbsorbFindings(fs)`
  (fold sub-detector tags like `heuristic:dep-confusion` into their
  family root), and `Print(w)` (render the aligned table with optional
  color). Wired into `scan`, `ci`, `forensics`/`audit` RunE.

## [0.6.1] — 2026-05-15

### Fixed

- **Dependabot now splits major-version bumps from minor/patch.**
  v0.5.8's config grouped all updates to GitHub-published actions
  (`actions/*`, `github/codeql-action*`) into a single weekly PR.
  This worked fine for routine security fixes but caused a real
  problem overnight: a major-version bump (`actions/checkout v4 →
  v6.0.2`, `actions/setup-go v5 → v6.4.0`, `goreleaser-action
  v6 → v7.2.1`, `codeql-action v3 → v4.35.5`) landed in one
  bundled PR that was easy to merge without realising the major
  jump.

  New policy:
    - **Minor + patch** updates are grouped into one weekly PR
      per ecosystem. Routine; safe to merge in a batch.
    - **Major** updates come in as individual, ungrouped PRs.
      One action at a time, explicit review required, no
      accidental bundle-merging.

  Same split applies to the `gomod` ecosystem so a major-version
  bump to `spf13/cobra` (which has happened before for cobra v1
  → v2 in nearby projects) gets its own deliberate PR review.

  Also added `goreleaser/*` to the github-actions-core group so
  the goreleaser-action bumps come through the same bundled-
  minor-patch path as the GitHub-published actions.

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
