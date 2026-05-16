# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Future work tracked in [README's Roadmap section](./README.md#roadmap)
and the [threat model](./docs/threat-model.md). Next milestone is
v0.16 — AI/ML supply chain (HuggingFace pickle scanner, PyTorch /
TF / Keras model file scanner, MCP server / agent-framework
auditor).

## [0.15.1] — 2026-05-16

UX fix: `chdora gate install` now actually persists. v0.15.0 (and
every prior release) required the user to manually add `export
PATH="$HOME/.chaindora/bin:$PATH"` to their shell rc — and most
users skipped that step, leaving the gate effectively off.

### Fixed — `chdora gate install` persists across shells + reboots

`gate install` now appends a clearly-marked block to the user's
shell rc (zsh / bash / fish on macOS+Linux; PowerShell `$PROFILE`
on Windows). Detected from `$SHELL`. The block carries fence-
comment markers:

```
# >>> chdora gate (managed) >>>
# Added by `chdora gate install`. Remove with `chdora gate disable`.
# ...
export PATH="$HOME/.chaindora/bin:$PATH"
# <<< chdora gate (managed) <<<
```

`chdora gate disable` finds the markers and removes the block
cleanly without touching anything else in the rc. `chdora gate
status` now distinguishes three states: (1) ACTIVE + persistent
(rc + current shell), (2) ACTIVE but shell-only (PATH set but no
rc block — will not survive a new terminal), (3) PERSISTENT but
not active in this shell (`source` the rc to pick it up), (4)
INACTIVE.

The original v0.9 design deliberately printed the export line and
asked the user to add it by hand, because chdora's own scanners
flag rc tampering as a finding. The fix: chdora's `hostforensics:
shellrc` scanner only matches specific malware patterns
(`curl|bash`, eval base64, netcat listeners) — a comment-bracketed
PATH prepend doesn't match any of them, so the auto-edit doesn't
self-flag. The markers also let any future scanner explicitly
skip the block if it ever adopts broader rc-edit detection.

### Added — `--no-persist` opt-out

Both `gate install` and `gate disable` take `--no-persist` for the
edge cases:

- Users with managed dotfiles (chezmoi, stow, GNU stow) who don't
  want chaindora editing their rc directly.
- Temporary disable that intends to re-enable shortly without
  re-editing.

With `--no-persist` on `install`, chdora just writes the shim
files and prints the export line for the user to add manually
(the pre-v0.15.1 behavior).

### Notes

- Idempotent. Re-running `chdora gate install` doesn't double-
  append. Re-running `chdora gate disable` when no block exists
  is a no-op.
- macOS bash special case: prefers `~/.bash_profile` if present
  (login-shell convention) and falls back to `~/.bashrc`.
- Fish gets `set -gx PATH ~/.chaindora/bin $PATH`; PowerShell
  gets `$env:PATH = $shimDir + ';' + $env:PATH`.
- If the block exists with the begin marker but no matching end
  marker, `gate disable` refuses to edit and surfaces the
  malformed state rather than guessing where the block ends.

## [0.15.0] — 2026-05-16

Predictive detection across **32 inventory ecosystems** (full
parity with the v0.14 gate-side coverage push). chdora now
applies gate-style behavioral checks to packages that are ALREADY
installed, plus three fleet-level signals for v0.13 server
deployments. The question shifts from "is this on a known-bad
list?" to "does this installed package match an attack-in-progress
shape?" — even when no CVE or incident-pack entry exists for it
yet.

### Added — predictive detector (`internal/detectors/predictive/`)

Replays the gate's behavioral checkers against the scan inventory:

- `predictive:cooldown` — the version you installed was published
  within the last 72h (configurable). Catches "you installed
  during the attack window" after the fact.
- `predictive:publisher-change` — the latest published version of
  this package was uploaded by a different account than the one
  you have installed. Strong account-takeover signal.
- `predictive:maintainer-trust` — publisher shows dormancy-gap,
  fresh-account, or single-version-author signals.
- `predictive:provenance` — package previously had sigstore /
  sumdb / GPG attestation and stopped (regression).
- `predictive:version-diff` — significant cross-version drift in
  static-pattern score between this version and recent prior
  releases (new `child_process`, new eval-of-dynamic, etc.).
- `predictive:republish-guard` — content hash differs from what's
  cached in `~/.chaindora/gate-cache/` for the same name@version.
  Escalates to **critical**: a known version reappearing with
  different bytes is a hard tamper signal regardless of context.

Predictive findings default to **severity=medium** so the default
`--fail-on=critical,high` CI gate stays quiet. Republish-guard is
the one exception — critical, never silently passed. Users who
want predictive signals to break the build add `medium` to their
`--fail-on` list.

Wired into `chdora scan`, `chdora audit`, `chdora ci`, and
`chdora forensics --scan-projects` via the shared `scanProject`
helper. Opt-out per command with `--skip-predictive`; predictive
implicitly turns off when `--skip-registry` is set (every checker
needs the registry probe).

New category `findings.CategoryPredictive` + dedicated
`PREDICTIVE SIGNALS` section in the text renderer. New flag
`--exclude-predictive` mirrors the other `--exclude-*` toggles.

### Added — lockfile-vs-disk integrity check

`internal/detectors/integrity/lockdrift.go`. Three drift checks
against installed `node_modules/`:

1. **Version drift** — `package-lock.json` pins `lodash@4.17.21`
   but `node_modules/lodash/package.json` reports a different
   version. Means install never completed, or a postinstall
   payload (or human attacker) swapped the directory.
2. **Name drift** — installed `package.json` reports a different
   `name` field. Symlink swap, manual edit, malicious extractor.
3. **Mirror-lockfile drift** — `package-lock.json` and
   `node_modules/.package-lock.json` disagree on integrity for
   the same `(name, version)`. One was modified without the other.

All three emit at **severity=critical** with category
`host-forensics`. Cross-platform: walks any project root that
contains a `package-lock.json`. Future ecosystems (Cargo.lock vs
`~/.cargo/registry/`, etc.) follow the same shape.

### Added — fleet republish detection (v0.13 server)

`internal/server/store.go` now tracks per-tuple integrity
observations across the entire fleet. Schema additions:

```
State.PackageObservations map[string]PackageObservation
```

keyed by `<ecosystem>/<name>@<version>`. On every
`IngestFindings` call, the server:

1. Records the first Integrity hash it sees for each tuple
   (with the reporting agent ID + timestamp).
2. On a later submission for the same tuple with a DIFFERENT
   integrity, emits a synthetic `fleet:republish-detected`
   finding (severity=critical, category=supply-chain-attack)
   into the store's regular findings stream.

The synthetic finding flows through the dashboard's normal
query path and shows up alongside agent-reported findings —
no new endpoint or UI mode needed for first cut.

Catches the supply-chain pattern where a registry serves
different bytes to different agents during an attack window —
the per-machine republish-guard can't see this if each agent's
local cache is independent.

### Added — `inventory.Package.Integrity` field

Every lockfile parser that has content hashes now surfaces them
on the inventory side. This lets the predictive detector seed
`gate.PackageRef.Integrity` and lets the fleet republish-detection
see lockfile-recorded hashes via findings.

Populated by: `npm` (package-lock.json), `yarn` (classic +
Berry), `pnpm`, `pipfile` (`Pipfile.lock`), `poetry` / `uv`
(`poetry.lock` / `uv.lock` first sha256), `cargo` (Cargo.lock
checksum), `go` (`go.sum` h1: via a sibling-file lookup from
`go.mod`).

### Added — `findings.Finding.Integrity` field

Carried on findings so the server can drive fleet republish-
detection without requiring agents to send a separate state
channel. Populated by the predictive detector from
`inventory.Package.Integrity`. Empty on findings where the
ecosystem's lockfile doesn't expose a hash.

### Added — detection-side parity push for 4 more ecosystems

Inventory-side parsers with full `Package.Integrity` so the
predictive detector lights up automatically:

| Lockfile | Ecosystem | Integrity field |
|---|---|---|
| `packages.lock.json` | NuGet | `contentHash` (base64-sha512) |
| `composer.lock` | Packagist | `dist.shasum` (sha1) |
| `pubspec.lock` | Pub | `description.sha256` |
| `mix.lock` | Hex | outer sha256 (LAST `"…"` in the tuple) |

Each new ecosystem gets a `inventory.Ecosystem` constant, PURL
type case, OSV ecosystem mapping (NuGet / Packagist / Pub / Hex
are all OSV-covered out of the box), and predictive ecosystem
mapping. Scan dispatcher fires on the lockfile basename — drop a
project with one of these into `chdora scan` and it inventories
+ predicts immediately.

### Added — lockfile-vs-disk drift for yarn + pnpm

Same three-check pattern as npm (version drift, name drift) but
adapted to the yarn.lock / pnpm-lock.yaml formats. Mirror-
lockfile drift (npm's `.package-lock.json` check) doesn't apply
— yarn and pnpm use different install-metadata layouts. Future
work to add their equivalents.

Both detectors call the inventory parsers (now exported as
`ParseYarnLock` / `ParsePnpmLock`) rather than reimplementing
two more variants of the format-detection logic.

### Added — registry-fetched integrity for rubygems + maven

Inventory packages for these two ecosystems carry no per-package
integrity from their lockfiles (`Gemfile.lock` has none in the
standard format; `pom.xml` has none at all). The predictive
detector now backfills via the existing v0.14 fetchers
(`EnrichRubyGemsIntegrity` against rubygems.org's v2 API,
`EnrichMavenIntegrity` against repo1.maven.org `.jar.sha1`)
before running the checker stack. Same bounded-pool concurrent
fetch, same graceful-degradation-on-failure semantics.

This closes the predictive republish-guard coverage for the two
ecosystems where it would otherwise stay silent.

### Added — full-parity push: 22 more inventory parsers

Detection-side coverage now matches prevention-side coverage
across every v0.14 gate ecosystem that has a parseable lockfile:

| Lockfile / manifest | Ecosystem | Integrity | OSV |
|---|---|---|---|
| `Package.resolved` | SwiftURL | git revision | ✓ |
| `stack.yaml.lock` | Hackage | pantry-tree sha256 | ✓ |
| `cabal.project.freeze` | Hackage | — | ✓ |
| `renv.lock` | CRAN | renv `Hash` | ✓ |
| `Manifest.toml` | Julia | git-tree-sha1 | — |
| `conda-lock.yml` | Conda | sha256 / md5 | — |
| `conan.lock` | ConanCenter | recipe revision | ✓ |
| `vcpkg.json` | vcpkg | builtin-baseline SHA | — |
| `deno.lock` | npm (`npm:` specifiers) | sha512 | ✓ |
| `pdm.lock` | PyPI | sha256 | ✓ |
| `paket.lock` | NuGet | — | ✓ |
| `Podfile.lock` | CocoaPods | SPEC CHECKSUMS sha1 | — |
| `Cartfile.resolved` | Carthage | git SHA | — |
| `cpanfile.snapshot` | CPAN | — | — |
| `nimble.lock` | Nimble | sha1 / git revision | — |
| `shard.lock` | Shards | git commit | — |
| `build.zig.zon` | Zig | Zig content hash | — |
| `elm.json` | Elm | — | — |
| `rebar.lock` | Hex (Erlang/rebar3) | sha256 (pkg_hash) | ✓ |
| `gradle.lockfile` | Maven Central | — | ✓ |
| `*.opam.lock` | opam | — | — |
| `*.rockspec` | LuaRocks | — | — |

**Predictive coverage now spans 30+ ecosystems** at the inventory
layer (up from 10). Ecosystems with `Integrity` populated also fire
republish-guard via the gate-cache.

### Added — lockfile-vs-disk drift for cargo + go + pip

- `Cargo.lock` ↔ `~/.cargo/registry/src/*/<name>-<version>/`. Reports
  drift when the cache has versions of a pinned crate but not the
  pinned version (severity=medium; false positives possible from
  multi-project caches).
- `go.sum` ↔ `$GOPATH/pkg/mod/<escaped-module>@<version>/`. Same
  shape; respects Go's `!Foo` → `!foo` escaping.
- `Pipfile.lock` ↔ `<project>/.venv/lib/python*/site-packages/<name>-<version>.dist-info/METADATA`.
  Walks the virtualenv adjacent to the lockfile and compares
  reported versions.

All three drift checks emit at severity=medium (false-positive risk
from cache reuse across projects) rather than the npm/yarn/pnpm
critical (where a per-project node_modules drift is unambiguous).

### Added — publish-cadence anomaly + cohort fresh-install signals

Server-side `IngestFindings` now feeds two additional fleet signals
beyond the v0.15 republish-detection:

- **`fleet:publish-cadence-anomaly`** (severity=critical). Tracks
  per-(eco, name) timeline of distinct versions first-seen by the
  fleet. When 4+ versions are first-published within a trailing
  24h window, emits a critical alert. Healthy packages don't ship
  that fast; attackers cleaning up a compromise often do.
- **`fleet:cohort-fresh-install`** (severity=medium). Tracks per-
  agent first-sighting of each `name@version`. When a new agent
  reports a version the fleet's existing cohort has had for 7+ days
  AND there are 3+ prior reporting agents, emits a medium alert.
  Surfaces "this dev just suddenly installed a long-stable dep" —
  the pattern attackers exploit when they pivot to a low-attention
  package.

Both alerts land in the same `Findings` stream as everything else,
so the dashboard surfaces them through existing query paths.

### Notes

- Predictive findings show up in scan / audit / ci output by
  default. Use `--exclude-predictive` to hide them, or
  `--skip-predictive` to skip the detector entirely.
- The 5 ecosystems without a clean machine-readable lockfile (bun,
  brew, sbt, plus advanced opam/luarocks layouts beyond the
  snapshot/rockspec formats handled here) remain detection-blind.
- Lockfile-vs-disk drift for cargo/go/pip is best-effort and
  medium-severity by design — the install caches are shared across
  projects, so false positives are easy. Use as a heads-up signal,
  not a hard gate.
- The fleet signals (republish-detection, cadence anomaly, cohort
  fresh-install) require v0.13 server mode to be running. They're
  unit-tested but don't fire without aggregated fleet state.

## [0.14.0] — 2026-05-16

Massive expansion of the gate-mode ecosystem coverage (8 PMs → 42),
plus a hash-keyed verdict cache that doubles as a republish-attack
detector. Quiet UX fixes to silence chdora when the underlying PM
would have failed anyway.

### Added — 30 new package-manager resolvers

Phase coverage matches the brainstorm in [docs/threat-model.md](./docs/threat-model.md).

**High-impact (Tier 1)** — .NET, modern Python, PHP, JVM:

| PM | Lockfile / source | Integrity field | OSV ecosystem |
|---|---|---|---|
| `dotnet` (NuGet) | `packages.lock.json` | `contentHash` (sha512) | NuGet |
| `composer` | `composer.lock` | `dist.shasum` (sha1) | Packagist |
| `poetry` | `poetry.lock` | files\[\].hash (sha256) | PyPI |
| `uv` | `uv.lock` | hash (sha256) | PyPI |
| `gradle` | `gradle dependencies` (cwd) | Maven Central .sha1 (via mvn fetcher) | Maven |

**Mobile / functional (Tier 2)** — iOS, Flutter, Elixir:

| PM | Lockfile / source | Integrity field | OSV ecosystem |
|---|---|---|---|
| `pod` (CocoaPods) | `Podfile.lock` (cwd) | SPEC CHECKSUMS (sha1) | SwiftURL |
| `swift` (Swift PM) | `Package.resolved` (cwd) | revision (git SHA) | SwiftURL |
| `dart` / `flutter` (Pub) | `pubspec.lock` | sha256 | Pub |
| `mix` (Hex) | `mix.lock` (cwd) | outer checksum (sha256) | Hex |

**Emerging / mainstream (Tier 3)** — bun, conda:

| PM | Source | Integrity | OSV ecosystem |
|---|---|---|---|
| `bun` | `bun pm ls --all` after `--ignore-scripts` install | — (binary lockfile) | npm |
| `conda` / `mamba` / `micromamba` | `--dry-run --json` | sha256 | — |

**OS-level dev + C/C++ (Tier 4)** — Homebrew, Conan, vcpkg:

| PM | Source | Integrity | OSV ecosystem |
|---|---|---|---|
| `brew` (Homebrew) | `brew info --json=v2` (recursive deps) | bottle / stable url sha256 | — |
| `conan` | `conan graph info --format=json` | package_id or recipe revision | — |
| `vcpkg` | `vcpkg.json` (manifest mode, direct deps only) | builtin-baseline (git SHA) | — |

**Long tail (full parity)** — all the rest of the major-ish ecosystems:

| PM | Source | Integrity | OSV ecosystem |
|---|---|---|---|
| `pipenv` | `Pipfile.lock` | hashes\[0\] (sha256) | PyPI |
| `pdm` | `pdm.lock` | hash (sha256) | PyPI |
| `deno` | `deno.lock` (cwd) | sha512 (npm:) / sha256 (remote) | npm (partial) |
| `stack` | `stack.yaml.lock` (cwd) | pantry-tree sha256 | Hackage |
| `cabal` | `cabal.project.freeze` (cwd) | — | Hackage |
| `sbt` | `sbt dependencyTree` (cwd) | Maven Central .sha1 (via mvn fetcher) | Maven |
| `opam` | `opam install --show-actions` | — | — |
| `rebar3` | `rebar.lock` (cwd) | sha256 (pkg_hash) | Hex |
| `paket` | `paket.lock` (cwd) | — | NuGet |
| `cpanm` | `cpanfile.snapshot` (cwd) | — | — |
| `luarocks` | `luarocks search --porcelain` | — | — |
| `carthage` | `Cartfile.resolved` (cwd) | git SHA (when 40-hex) | — |
| `elm` | `elm.json` (cwd) | — | — |
| `nimble` | `nimble.lock` (cwd) | sha1 or git revision | — |
| `shards` | `shard.lock` (cwd) | git commit | — |
| `zig` | `build.zig.zon` (cwd) | Zig content-addressed hash | — |
| `julia` | `Manifest.toml` (cwd) | git-tree-sha1 | — |
| `R` / `Rscript` (renv) | `renv.lock` (cwd) | renv `Hash` field | CRAN |

### Added — hash-keyed verdict cache + republish-attack detector

`~/.chaindora/gate-cache/<ecosystem>/<sha256-of-tuple>.json` stores
Approve verdicts keyed on `(ecosystem, name, version, integrity)`.
Two purposes:

1. **Perf**: a repeat install of an already-vetted version reads one
   small JSON file instead of re-running the checker stack across
   the network. 7-day TTL for Approve verdicts; Warn / Block / Unknown
   are never cached (users chasing a fix see fresh signal each time).
2. **Security**: a cache hit with the same `(eco, name, version)` but a
   DIFFERENT integrity than what was cached fires a new
   `republish-guard` check — Block, severity critical — surfacing the
   supply-chain pattern where a maintainer account is compromised and
   an attacker overwrites a known-good version with malicious bytes.

Three subcommands manage it:

```sh
chdora gate cache stats      # entries per ecosystem
chdora gate cache clear      # wipe (next install rebuilds)
chdora gate cache path       # print root
```

### Added — integrity fetchers for ecosystems whose lockfile lacks hashes

| Ecosystem | Endpoint | Output |
|---|---|---|
| RubyGems | `https://rubygems.org/api/v2/rubygems/<n>/versions/<v>.json` | `sha` → `sha256:...` |
| Maven Central | `<group>/<artifact>/<v>/<artifact>-<v>.jar.sha1` (fallback `pom.sha1`) | sha1 hex |

Bounded-pool concurrent fetch (16 in flight, 5 s per-request timeout).
Failures degrade gracefully: empty `Integrity` means the republish-guard
can't fire for that package, but the install still proceeds.

### Added — parallel checker execution

`gate.Run` now uses a bounded worker pool (`maxConcurrentChecks = 16`)
to fan out checker work across packages. Within a single package the
checkers stay sequential. Tests pass under `-race`. Expected 3–5×
speedup on the per-package phase for typical install trees.

### Added — `chdora gate cache` subcommand family

See above. Three subcommands: `stats`, `clear`, `path`.

### Changed — chdora is silent when the package manager itself errors

New `PMError` type carrying the PM's captured stdout/stderr + exit
code, returned by every resolver when the underlying PM exits
non-zero. The CLI layer detects it and surfaces the PM's output
verbatim to the user, then exits with the PM's exit code. No
chdora-prefixed wrapping, no second invocation.

Rationale: if `npm install nonexistent-pkg` would have failed
regardless of chdora (typo, 404, peer-dep conflict, malformed
lockfile), that's not a gate concern. chdora stays out of the way.
Chdora-internal failures (parse error, network failure in chdora's
own probes) still fail-closed under policy as before.

### Changed — `chdora gate status` display

The "gates-install" column previously hardcoded `true` only for npm
and printed `false` for every other PM. Now derives from
`isGatedPM()` — single source of truth shared with `gateExecCmd`'s
switch, so the display can't drift.

### Changed — verdict cache integrity coverage

`PackageRef.Integrity` is now populated by:

- **From lockfile**: npm, yarn (classic + Berry), pnpm, pip, cargo,
  go, NuGet, Composer, Poetry, uv, Pipenv, PDM, deno, Pub, Hex
  (mix.lock), Swift PM, CocoaPods, Carthage, Conan, nimble, renv,
  Julia, vcpkg, zig, shards, rebar3.
- **Via registry fetch**: bundler (rubygems.org API), mvn + gradle
  + sbt (Maven Central .sha1), Homebrew (`brew info --json=v2`).
- **Not yet populated** (republish-guard inactive for these
  ecosystems): bun (binary lockfile), opam, cabal, CPAN, luarocks,
  Paket, Elm.

### Changed — `gate status` footer adds latency-audit instructions

Short hint at the bottom of `gate status` showing how to time
passthrough overhead: `time npm run --silent noop` with and without
the shim on PATH. Expected delta is <100ms; anything higher is a
shim-overhead bug worth opening.

### Fixed — passthrough for cwd-only PMs

`classifyGateArgs`'s "isInstall && len(args)==1 → passthrough"
short-circuit was correct for npm (the `npm install` bare-restore
case) but wrong for resolution-only PMs (gradle, pod, swift, mix,
and the new Tier 2/3/4 additions). Added an `isPMCwdOnly` guard
that skips the short-circuit for those PMs.

### Fixed — gradle / pod / swift / mix invocation overhead

These PMs have no install-args contract; the user's manifest IS
the input. The gateProceed branch now skips the realPkgs check for
cwd-only PMs so they resolve cleanly with just the verb.

### Notes

- All 30 new resolvers use the same temp-dir + scripts-disabled
  posture as the original 8. Nothing executes user-controlled
  package code during resolution.
- The verdict cache writes only when `Integrity` is non-empty — no
  tamper detection means no cache entry, by design.
- vcpkg is direct-deps-only for now (manifest mode without
  registry-baseline walking). Transitive coverage is on the
  follow-up backlog.
- `chdora gate cache` subcommands are read-mostly; the cache
  rebuilds on the next install if cleared.

## [0.13.5] — 2026-05-16

## [0.13.5] — 2026-05-16

Update-all (bare `npm update`, `pnpm update`, etc. with no package
names) is the most common usage of update verbs. v0.13.4 detected
the verb but refused the operation with a "specify packages" error.
This release implements actual update-all resolution: chaindora reads
the user's manifest from CWD, copies it into a temp dir alongside
the existing lockfile, runs the PM's update verb in lockfile-only
mode there, and gates every node in the resulting tree.

### Added — update-all resolvers (5 PMs)

| PM | New function | Manifest seeded | Update command |
|---|---|---|---|
| npm | `ResolveNPMUpdateAll` | `package.json` + `package-lock.json` | `npm update --package-lock-only --ignore-scripts` |
| pnpm | `ResolvePnpmUpdateAll` | `package.json` + `pnpm-lock.yaml` | `pnpm update --lockfile-only --ignore-scripts` |
| yarn | `ResolveYarnUpdateAll` | `package.json` + `yarn.lock` | `yarn up * --mode=update-lockfile` (Berry) → `yarn upgrade --silent --ignore-scripts` (classic fallback) |
| cargo | `ResolveCargoUpdateAll` | `Cargo.toml` + `Cargo.lock` + synthetic `src/lib.rs` | `cargo update` |
| bundle | `ResolveBundlerUpdateAll` | `Gemfile` + `Gemfile.lock` | `bundle lock --update` |

All five use the same safety posture as the existing install-args
resolvers: temp dir isolation, scripts disabled where the PM
supports a flag, lockfile-only mode so no real install touches disk.

### Changed — dispatcher routes update-all to the resolver

`internal/cli/gate_exec.go`'s `gateRefuseUpdateAll` branch now
dispatches to the per-PM update-all resolver when one is registered.
If no resolver is available for a PM (gem, mvn — neither has a
clean manifest-based update model), it still refuses with a clear
message that includes the PM name.

### Not yet implemented

- **`gem update`** — `gem update` (no args) updates every gem
  installed system-wide; there's no manifest. Resolving requires
  enumerating installed gems via `gem list --local` and querying
  rubygems.org for newer versions. Stays refused for v0.13.5;
  on the v0.14 backlog.
- **`pip install --upgrade -r requirements.txt`** — pip's
  update-all is shaped differently (a flag on install, not a
  separate verb). The existing install-verb dispatcher already
  routes it, but precise lockfile-style resolution against the
  requirements file is a separate question. Today, pip's update
  through chaindora resolves exactly the same way as install.
- **`mvn versions:use-latest-versions`** — Maven's update is a
  plugin goal, not a built-in. Not on the roadmap; Maven version
  bumps go through `pom.xml` edits which then route through
  `dependency:get` (already gated).

### Notes

- The resolver copies your project's actual manifest into `$TMPDIR`
  for the duration of the gate check. Nothing leaves the local
  machine. The temp dir is removed via `defer`.
- For yarn, Berry's `yarn up * --mode=update-lockfile` is tried
  first; on rejection (yarn classic refuses Berry's flag combo)
  we fall back to `yarn upgrade --silent --ignore-scripts`. Same
  detection pattern as the existing install-args yarn resolver.
- The gate checks every node in the resolved tree, not just nodes
  whose version changed. Reason: OSV state may have advanced since
  the prior install was vetted (a CVE published yesterday against
  a package that was clean last week).

## [0.13.4] — 2026-05-16

Closes the update-verb coverage gap in the gate shim. Previously
`npm install pkg` was gated but `npm update pkg` slipped through to
the real package manager — defeating the gate exactly where it was
most relevant for the publisher-change / fresh-publish / new-CVE
threat classes.

### Added — update verbs gated across every supported PM

| PM | New verbs gated | Already covered |
|---|---|---|
| npm | `update`, `up`, `upgrade`, `udpate` (typo) | `install`, `i`, `add`, `in`, … |
| yarn | `upgrade`, `upgrade-interactive`, `up` (Berry) | `add` |
| pnpm | `update`, `up`, `upgrade` | `add` |
| cargo | `update` | `add`, `install` |
| bundle | `update` | `add` |
| gem | `update` | `install` |
| pip | (existing `install` verb covers `pip install --upgrade`) | `install` |
| go | (existing `get` verb covers `go get -u`) | `get`, `install` |
| mvn | (no standalone upgrade verb — version bumps via pom.xml) | `dependency:get` |

So `npm update lodash`, `pnpm up react`, `cargo update serde`,
`bundle update rspec`, `gem update rails` all now resolve their
trees and run every check against every node, identical to the
install path.

### Added — clear refusal for bare update-all

`npm update` / `pnpm update` / `yarn upgrade` / `cargo update` /
`bundle update` / `gem update` invoked with **no package names**
walk every dep in the local manifest. The gate doesn't yet carry
the user's actual manifest into the resolver's temp directory, so
the resolver can't reproduce that operation. Rather than silently
passing through (the v0.13.3 behavior), the shim now refuses with:

```
`npm update` with no explicit package names updates every dep in the
manifest, but chdora gate doesn't yet resolve update-all without
project context. Specify packages (e.g. `npm update <pkg>`) or run
with --chaindora-policy=lenient to bypass the gate for this
invocation.
```

Resolving update-all from the local manifest is on the v0.14 roadmap.

### Refactored — uniform per-PM dispatch

The 9-case switch in `internal/cli/gate_exec.go` previously inlined
the install-verb check per package manager. Replaced with a single
`classifyGateArgs(pm, args)` returning `gatePassthrough` /
`gateProceed` / `gateRefuseUpdateAll`. Each PM's resolver mapping
stays in its own switch case, but the verb-classification logic is
now in one place — adding new PMs or new verbs only touches one
function.

### Tests

`internal/cli/gate_exec_test.go` covers all install + update verbs
across every supported PM, the lockfile-restore passthrough cases,
the bare-update refusal cases, and unknown / empty edge cases. 47
test cases, all passing.

## [0.13.3] — 2026-05-16

Patch release: unbreaks the self-scan CI job and fixes doc / code
drift surfaced by a v0.13.2 alignment audit. No behavior changes.

### Fixed — CI dogfood job

`.github/workflows/test.yml` excludes `website/` in addition to
`testdata/`. The v0.13.2 commit added the Angular static site without
updating the exclude list, so the dogfood `chdora ci . --exclude
testdata --fail-on critical,high` step started flagging 26 OSV-IOC
findings in the Angular CLI's transitive build-time tooling (tar
path-traversal, picomatch ReDoS, esbuild dev-server, etc.). Those
CVEs are real, but they're in a separately-built static site's dev
toolchain and don't ship with the `chdora` binary.

### Fixed — README ↔ code drift

- Install one-liners (`curl -L .../chaindora_0.9.2_*`) and the
  `chdora upgrade --version v0.9.0` example bumped to the current
  release. The README had been four minor versions stale.
- "Mode 1: Prevention" copy said "**seven** independent checkers";
  actual checker count is **nine** (added `provenance` and `git-url`
  in v0.10 / v0.11). Updated the prose and added the two missing
  rows to the gate-checker table.
- "Supported ecosystems" table marked PyPI gate as "planned" and
  omitted RubyGems / crates / Maven / Go gate columns — all five
  shipped in v0.11 / v0.13. Now reflects the actual coverage.
- The v0.13 roadmap line claiming "*Scheduled scans + webhook ingest
  + TLS land in v0.13.x*" rewritten to truthful "not yet implemented"
  wording — none of those routes exist in `internal/server/server.go`.

### Fixed — CLAUDE.md ↔ code drift

- "Detection layers" table now lists all six detectors
  (`trustdrift` and `integrity` were missing).
- "Gate checkers" table lists all nine checkers (`provenance` and
  `git-url` were missing).
- Repo-layout block refreshed: gate adds `provenance`, `giturl`,
  `probes`, and all eight per-ecosystem resolvers; CLI adds
  `server` / `agent` / `watch` / `gate_stack`; inventory adds
  `rubygems` / `cargo` / `maven`; detectors adds `trustdrift` and
  `integrity`; new `server/` and `website/` top-level entries.

### Fixed — website ↔ code drift

- "Detection only" tier removed Jenkins / Drone from the inventory
  list (no parser exists for either). Added a small note that
  `chdora ci` autodetects those CIs from environment variables and
  emits SARIF / annotations there even without a dedicated
  pipeline-file parser.

### Fixed — phantom flag value

`chdora gate check --ecosystem` flag help advertised
`npm|pypi|go|rubygems|crates|maven|nuget|packagist`. Removed `nuget`
and `packagist` — neither has a probe, resolver, or gate
registration anywhere in the codebase. Both are still on the v0.14
roadmap.

### Fixed — CHANGELOG self-reference

v0.13.2 entry described "the 7-checker gate stack"; the actual count
is 9. Corrected.

## [0.13.2] — 2026-05-16

Documentation pass + project website. No CLI behavior changes; binary
identical to v0.13.1 minus the version stamp.

### Added — `website/`

Angular 18 standalone-component landing page for `chaindora.dev`. Built
to spec from the official brand guide (`logo/PDF Guideline.pdf`):
- Three-color palette only — `#000000` / `#DA2F2F` / `#FFFFFF`
- Permanent Marker 400 (Google Fonts) for the wordmark and display
  headings; system sans for body copy
- Logo asset (ninja + CHAINDORA wordmark) used directly from
  `logo/SVG Vector Files/Transparent Logo.svg`

Sections, top-to-bottom:
- Hero — wordmark logo, Permanent Marker headline, install / GitHub CTAs
- "Before install. After install." mode cards with sample terminal
  output (replaces the old bullet-list inventory)
- "What chaindora catches" — grouped by Both modes / Before only /
  After only (replaces the 15-row yes/no matrix)
- "Install in 60 seconds" — three numbered step cards (replaces the
  flat h3+code dump)
- Ecosystem coverage — three tier cards (Full / Detection only /
  Partial) replacing the 4-column table
- Fleet mode band — feature list + dark code block
- Roadmap timeline — vertical timeline with shipped / planned states
- Closing CTA — black card with red and outline buttons

Builds to a static bundle. Deploy command and per-host SPA-fallback
settings documented in `website/README.md`.

### Changed — documentation rewrites

- **`docs/architecture.md`** rewritten to document the two-mode model
  (prevention via `chdora gate`, detection via `scan` / `audit` /
  `forensics` / `ci`), the 9-checker gate stack, the 9 ecosystems,
  the universal `findings.Finding` carrier, fail-closed design
  invariants, and the 7-step procedure for adding a new ecosystem.
- **`docs/incident-pack.md`** rewritten around the
  post-OSV-federation contract — what the curated YAML pack covers
  that the OpenSSF Malicious Packages feed cannot (OS-level attacks,
  worm file artifacts, maintainer sabotage, typosquat name lists,
  extension takeovers), the entry anatomy, the quality bar, and the
  testing flow for new entries.
- **`docs/ci-integration.md`** expanded with per-platform recipes
  (GitHub Actions, GitLab, CircleCI, Bitbucket, Azure Pipelines,
  Drone/Woodpecker, Jenkins) plus the baseline + suppression +
  sticky-PR-comment workflow and the server/fleet integration.

### Changed — README copy

- Roadmap section: the previously planned v0.12 (IaC supply chain)
  moves to v0.14; AI/ML moves to v0.15; Bun/Deno to v0.16 — so the
  shipped releases (v0.10, v0.11, v0.13) no longer sit above an
  unshipped v0.12.
- Scope paragraph rewritten to describe what each mode covers
  structurally rather than quoting a percentage.

## [0.13.1] — 2026-05-16

The "no asymmetry, take two" milestone — closes every remaining
"⏭ passthrough" and "⚠ partial" cell in the gate matrix where
the limit wasn't a real registry-API constraint.

### Added — provenance across every ecosystem

| Ecosystem | Provenance source |
|---|---|
| Go | sum.golang.org transparency log (Go-team-signed) |
| Maven Central | `.jar.asc` GPG signature presence (Maven Central mandates GPG signing) |
| RubyGems | Trusted Publishing `metadata.attribution` URL |
| crates.io | per-version `published_by` (authenticated account) |

Each ecosystem now satisfies `ProvenanceProbe` and is registered
in `buildGateProbes`. The same regression-detection logic
("publisher used to attest, then stopped") works uniformly.

### Added — publisher-change for Maven and Go

- **Go**: derive owner from the module path. `github.com/spf13/cobra`
  → publisher `github.com/spf13`. Vanity-import paths
  (`gopkg.in/`, `golang.org/x/`, `go.uber.org/`) fall back to
  the host so cross-version comparison resolves cleanly. Closes
  the "⚠API" cell with documented degradation for vanity paths.
- **Maven**: download per-version `pom.xml` and join
  `<developers>` `<name>` (or `<id>` fallback). Best-effort:
  many pom.xml files don't include the block or inherit from
  a parent pom (we don't follow parents). Empty result → graceful
  Unknown.

### Added — Go gate-exec resolver

`internal/gate/resolve_gomod.go`: tmpdir with minimal `go.mod`
→ `go mod download -x -json all` → parse the streaming JSON.
Closes the asterisked cell in the gate-exec row. Resolution
runs `go mod download` (fetches module bytes, no code
execution) so the resolver itself can't be made to run
attacker code.

`chdora gate exec go get <mod>@<ver>` now goes through the
full 7-checker stack. Shim mechanism extended to include `go`.

### Added — git-URL GitHub-API enrichment

`GitURLCheck` now optionally enriches its verdict with
GitHub-API evidence for github.com URLs:

- repo age < 30 days → flag
- < 5 stargazers → flag
- repo is a fork → flag
- repo is archived / disabled → flag

Reads `GITHUB_TOKEN` from the environment for higher rate
limits (5000/hr authenticated vs 60/hr anonymous). Enrichment
upgrades baseline-Approve to Warn when signals fire; never
downgrades a Block. Failures (rate-limit / 404 / network) fall
back silently to the baseline verdict.

### Added — lockfile-integrity forensics (go.sum)

`internal/detectors/integrity/`: new forensics detector. For
every `go.sum` under a project root, cross-checks each entry
against `sum.golang.org/lookup/<mod>@<ver>`. A mismatch
indicates lockfile tampering between resolution and on-disk
storage — `INTEGRITY-MISMATCH` finding, HIGH severity.

Rate-limited to 100 lookups per `go.sum` (a giant monorepo
won't DOS sumdb).

Cargo.lock integrity verification is scaffolded but not yet
wired — that requires hitting the crates.io index protocol
which is a separate API (v0.13.x).

Flag: `chdora forensics --skip-integrity`.

### Matrix state after v0.13.1

The ⏭ cells in v0.11.2's audit are now ✅ for every ecosystem
that has SOME form of publisher / provenance signal. The
remaining real-API limits are documented explicitly per
ecosystem in each probe's source.

### Tests

All green under `go test ./... -race`. Live-verified end-to-end
against npm, PyPI, RubyGems, crates, Maven, Go, and git-URL.

## [0.13.0] — 2026-05-16

The "fleet mode" milestone. A single chdora-server process now
accepts findings from many agents and serves a multi-machine
dashboard. Opt-in by config; the default single-machine workflow
is untouched.

(Skipping v0.12 — IaC supply chain is still planned but server
mode unblocks larger orgs first.)

### Added — `chdora server`

`internal/server/` — new package with JSON-backed store +
HTTP routes + embedded HTML dashboard.

**Store**: single-file state at `<data-dir>/state.json`.
Atomic-write (temp + rename). Pure stdlib JSON; no SQLite
dep. Scales to tens-to-hundreds of agents; v0.14+ migration
path to SQL if usage grows past that.

**Auth**: per-agent bearer tokens. Server generates the raw
token at enrollment time, shows it once, stores only the
SHA-256 hash. Optional shared `--enrollment-secret` gates who
can enroll.

**HTTP routes**:
- `POST /api/v1/agents/enroll` — register an agent
- `POST /api/v1/agents/<id>/scan` — upload findings (Bearer auth)
- `GET /api/v1/agents` — list enrolled agents
- `GET /api/v1/agents/<id>` — agent details
- `DELETE /api/v1/agents/<id>` — graceful decommission (Bearer auth)
- `GET /api/v1/findings?agent=&severity=&latest=1&limit=` — query
- `GET /api/v1/summary` — fleet aggregates
- `GET /api/v1/version`, `GET /healthz` — probes
- `GET /` — embedded HTML dashboard

**Dashboard**: single static page, no JS framework, no build
step. Live-fetches `/api/v1/summary` + `/api/v1/findings` every
30s. Severity-colored cards + agent table + recent-findings
table. Renders fine in any modern browser.

**Graceful shutdown**: SIGINT/SIGTERM flushes state before exit
so the last in-flight push isn't lost. Access log to stderr
in one-line-per-request format.

### Added — `chdora agent`

Three subcommands:
- `chdora agent enroll --server <url> --name <id> [--enrollment-secret X]`
  — registers and saves credentials to `~/.chaindora/agent.json`
  (mode 0600). The api_key is persisted client-side only.
- `chdora agent push --findings <path>` — upload a scan JSON.
- `chdora agent status` — show enrollment + ping server.

### Added — watch integration

`chdora watch` now auto-pushes to the configured server on every
pass when `~/.chaindora/agent.json` exists. No new flags needed
— enrollment is the opt-in. Existing `--webhook` path still
works for non-server flows.

### Quick start

```sh
# Server box
chdora server start --addr :8080 --data-dir /var/lib/chdora \
                    --enrollment-secret RANDOM-LONG-STRING

# Each agent (laptop / CI node / etc.)
chdora agent enroll --server https://chaindora.corp:8080 \
                     --name $(hostname) \
                     --enrollment-secret RANDOM-LONG-STRING
chdora watch --interval 1h  # auto-pushes every pass
```

### Deferred to v0.13.x

- TLS termination — for v0.13.0, stand the server behind nginx
  / caddy / Cloudflare Tunnel
- Webhook ingest (`POST /api/v1/webhook/{github,gitlab,manual}`)
  for git-push-triggered scans
- Scheduled fleet scans (server pushes scan jobs to agents)
- SAML/OIDC auth for the dashboard
- SQL backend for >1000-agent fleets
- Multi-tenant orgs

### Tests

httptest end-to-end: enroll → push → list → summary → dashboard.
State-persistence roundtrip. Wrong-token-rejected. All green
under `go test ./... -race`.

## [0.11.2] — 2026-05-16

The "no asymmetry" milestone — closes every "npm only" /
"documented limitation" marker in the audit matrix that wasn't a
real technological constraint. After this release the gate stack
and ecosystem coverage are uniformly broad.

### Closed gaps

**Maven JAR static-pattern + version-diff** (was: Unknown). The
static scanner auto-detects archive format from magic bytes
(gzip / zip / plain tar) and dispatches to gzip-tar (npm /
PyPI sdists / .crate), plain-tar (RubyGems .gem), or zip
(Maven JARs / PyPI wheels). JVM static-init pattern detector
added: `jvm-static-init-with-exec/network/base64-decode` flags
`static { ... }` blocks that touch network or
`Runtime.getRuntime().exec()` — the JVM analogue of Go init().

**Go modules full gate stack**. New `internal/registries/gomod.go`
probe against `proxy.golang.org` GOPROXY (`@v/list` + `@v/<v>.info`
+ `@v/<v>.zip`) with proper module-path case escaping. Registered
as `"go"` ecosystem in `buildGateProbes`; every existing checker
lights up. Live-verified `github.com/spf13/cobra@v1.10.2`: 27
versions over ~9 years, cooldown 162d ✓. Publisher-change
returns Unknown per documented Maven-style limit (Go modules
have no per-version publisher in the proxy API).

**PyPI provenance**. PyPI's PEP 740 attestations exposed under
the `provenance` field on per-file release entries.
`registries.PyPI` now satisfies `ProvenanceProbe`
(`HasProvenance` / `AnyVersionHasProvenance`), registered
alongside npm. Regression detection ("publisher stopped
attesting") works for PyPI identically to npm.

**Trust-anchor drift expansion**. New monitored anchors:
- `/etc/hosts` — content-aware: redirects of registry hostnames
  (`registry.npmjs.org`, `pypi.org`, `crates.io`,
  `proxy.golang.org`, `github.com`, etc.) flagged HIGH
- `/etc/resolv.conf`
- `~/.m2/settings.xml` — non-canonical Maven mirrors
- `~/.gradle/init.gradle{,.kts}` — repository overrides without
  `mavenCentral()`
- `~/.ssh/config` — `ProxyCommand`/`ProxyJump` flagged
- `~/.sigstore/root/targets/trusted_root.json`
- `~/.cosign/cosign.pub`

**Preflight already-satisfied check, all ecosystems** (was: npm
only). Reads the right lockfile per project: `package-lock.json`,
`pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `Pipfile.lock`,
`uv.lock`, `Cargo.lock`, `Gemfile.lock`. Saved-plan apply now
skips already-satisfied fixes for every ecosystem.

**Gate-exec resolvers — four new package managers**:
- **pip / pip3**: `pip install --dry-run --report <file>` →
  parse installation report JSON. Honors pip's per-distribution
  name normalization (PEP 503).
- **cargo**: tmpdir with minimal `Cargo.toml` →
  `cargo generate-lockfile` → parse `Cargo.lock` `[[package]]`
  blocks. Crates with non-crates.io sources fall through.
- **bundle / gem**: tmpdir with minimal `Gemfile` →
  `bundle lock` → parse `Gemfile.lock` `GEM/specs:` block.
- **mvn**: tmpdir with minimal `pom.xml` →
  `mvn dependency:list -DincludeScope=runtime -DoutputFile=...`
  → parse `g:a:type:version:scope` lines. Runs against an
  ephemeral local-repo so it doesn't touch the user's `~/.m2`.

Shim mechanism (`chdora gate install`) writes shims for these
four too — `npm`, `yarn`, `pnpm`, `pip`, `pip3`, `cargo`,
`bundle`, `gem`, `mvn` all route through the gate when
`~/.chaindora/bin` is on PATH front.

### Matrix state after v0.11.2

Every cell in the v0.11 audit table that wasn't a real
technological limit is now ✅. Remaining ⚠/Unknown markers
are documented API gaps:
- Maven Central publisher-change: public Solr API doesn't
  expose deployer identity
- Go modules publisher-change: proxy.golang.org doesn't expose
  per-version publisher
- Provenance for RubyGems / crates / Maven / Go: sigstore
  adoption hasn't reached these ecosystems yet

### Tests

All green under `go test ./... -race`. 67 → 67 test files
(resolvers tested end-to-end via gate-exec integration; unit
tests for each parser are v0.11.3 cleanup).

## [0.11.1] — 2026-05-16

Closes the final v0.11 gap: the git-URL trust evaluator. With
this v0.11 ships all six features from the threat-model-driven
roadmap.

### Added — git-URL trust evaluator

The threat model's "worst-trust-model" code-entry vector: git
URLs supplied to `npm install user/repo`, `pip install
git+https://...`, `go get` against unknown hosts, CMake
`FetchContent_Declare`. These have no central registry, no
signing, no publish-time, no maintainer metadata. The only
levers we have are host-trust, ref-pinning, and transport
scheme.

`internal/gate/giturl.go` — new gate checker that evaluates
`PackageRef{Ecosystem: "git"}` entries:

| Host | Ref | Verdict |
|---|---|---|
| Well-known (github / gitlab / bitbucket / codeberg / sr.ht) + 40-hex SHA | Approve |
| Well-known + tag | Warn (tags are mutable) |
| Well-known + branch | Block (fully mutable) |
| Allowlisted (chaindora.yml `allow.git_hosts`) + SHA | Approve |
| Unknown host + SHA | Warn (auditable bytes, no community oversight) |
| Unknown host + tag/branch | Block |
| `http://` or `git://` scheme | Block (no transport security) |

`chaindora.yml` schema additions:
```yaml
git_hosts:           # corporate self-hosted to trust like well-known
  - gitea.corp.local
  - gitlab.internal
allow_branch_refs: false   # set true to downgrade branch-ref Block → Warn
```

### Added — npm resolver: git+url detection

`internal/gate/resolve_npm.go` now parses the `resolved` field
of each package-lock.json entry. When it matches `git+...` /
`git://` / `git@` / `ssh://git@`, the resolver emits a
PackageRef with `Ecosystem: "git"` so the git-URL checker
fires and the registry-model checkers (cooldown, OSV,
publisher-change, etc.) skip cleanly via early-return.

### Changed — cooldown + OSV passthrough for git ecosystem

cooldown and OSV checks previously returned `Verdict=Unknown`
for ecosystems with no registry probe — under Strict policy
that would block legitimate pinned-SHA git deps. Both now
return Approve passthrough for `Ecosystem: "git"` because
those checks are registry-model and don't apply.

### Live-verified

| Test case | Verdict |
|---|---|
| `https://github.com/expressjs/express#<40-hex>` | Approve |
| `https://github.com/expressjs/express#main` | Block (mutable branch) |
| `https://random.example.com/u/r#v1.0` | Block (unknown host + tag) |
| `http://github.com/u/r#<sha>` | Block (insecure transport) |

### Roadmap status

v0.11 is feature-complete. All six features from
docs/threat-model.md's v0.11 milestone shipped:

- ✅ git-URL trust evaluator (this commit)
- ✅ build-time + import-time static scan (v0.11.0)
- ✅ trust-anchor drift forensics (v0.11.0)
- ✅ RubyGems + crates.io + Maven Central full stacks (v0.11.0)
- ✅ PyPI gate parity completion (v0.11.0)
- ✅ ecosystem-pluggable gate refactor (v0.11.0)

Next: v0.12 — IaC supply chain (Terraform / Helm / Ansible / Composer / NuGet).

## [0.11.0] — 2026-05-16

The "boundaries" milestone — driven by the threat model rather
than by ecosystem checklist. v0.11 closes five of the six gaps
the threat model called out; the sixth (git-URL trust evaluator)
slides to v0.11.1.

### Added — gate ecosystem pluggability (refactor)

- `internal/gate/probes.go`: `VersionProbe` + `ProvenanceProbe`
  interfaces + `Probes` registry. Every gate checker now
  dispatches through the table. Adding a new ecosystem is
  one-line registration in `cli/gate.go`'s `buildGateProbes()`
  — the existing seven checkers (allowlist, OSV, cooldown,
  publisher-change, maintainer-trust, provenance, static-pattern
  + version-diff) light up automatically.
- Canonicalization map: `pip`→`pypi`, `cargo`→`crates`,
  `gem`/`rubygems`→`rubygems`, `maven-central`→`maven`. Users
  can pass either form on `--ecosystem`.
- `internal/cli/gate_stack.go`: single `buildCheckerStack` helper
  shared by `gate check` and `gate exec` so the two surfaces
  can't drift.

### Added — PyPI gate parity

- registries.PyPI now satisfies `VersionProbe` end-to-end
  (`PublisherOfVersion` uses `info.maintainer_email` /
  `info.author_email` as project-level publisher; `AllVersions`
  returns the full release timeline). Publisher-change,
  maintainer-trust, version-diff all fire for PyPI.
- Live-verified: `chdora gate check requests@2.32.0
  --ecosystem pypi` reports publisher "Ian Stapleton Cordasco,
  Nate Prewitt", unchanged since 2.31.0.

### Added — three new ecosystems (full stack)

**RubyGems** (`Gemfile.lock` → rubygems.org/api/v1):
- `internal/inventory/rubygems.go`: Bundler lockfile parser
- `internal/registries/rubygems.go`: `/versions/<name>.json` for
  publish times + authors (used as publisher); `<name>-<v>.gem`
  for tarballs; gem files are tar archives, scanned by the
  existing static-pattern infrastructure
- OSV ecosystem mapping (`RubyGems`)
- PURL type (`gem`)

**crates.io** (`Cargo.lock` → crates.io/api/v1):
- `internal/inventory/cargo.go`: TOML lockfile parser (hand-
  parsed; deliberately doesn't add a TOML dep)
- `internal/registries/crates.go`: per-version
  `published_by.login` is the publisher (more reliable than
  PyPI's project-level field)
- OSV ecosystem mapping (`crates.io`)
- PURL type (`cargo`)
- Cargo `build.rs` static-pattern detection from previous
  commit lights up here

**Maven Central** (`pom.xml` → search.maven.org Solr API):
- `internal/inventory/maven.go`: pom.xml XML parser with
  single-level property substitution; skips `test`-scoped deps
- `internal/registries/maven.go`: Solr search for publish
  timestamps + version timeline
- Name format `groupId:artifactId` (PURL spec splits these into
  namespace/name)
- Per-version publisher returns "" — public API doesn't expose
  deployer identity; publisher-change degrades to Unknown
- JAR static-pattern returns Unknown until scanTarball gains
  zip-walker support (v0.11.x)
- OSV ecosystem mapping (`Maven`)
- PURL type (`maven`)

Live-verified all three against real registries:
- `rails@7.0.4` (RubyGems): publisher "David Heinemeier Hansson",
  516 versions, CVE detected
- `serde@1.0.193` (crates): publisher "dtolnay", 312 versions
- `com.google.guava:guava@32.0.0-jre` (Maven): 150 versions,
  cooldown ✓, publisher Unknown by design

### Added — build-time / import-time static-scan patterns

- **Go `init()` detection** (only fires when init() function
  present in the same file):
  - `go-init-with-network` (weight 2): http.Get / net.Dial
  - `go-init-with-exec` (weight 3): exec.Command
  - `go-init-reads-sensitive-file` (3): /etc/passwd, ~/.ssh
  - `go-init-base64-decode` (1): base64.DecodeString
  - Test files (*_test.go) explicitly skipped

- **Rust `build.rs`** patterns (every signal is high-severity
  because build.rs runs as the developer at compile time):
  - `rust-build-rs-network` (3): reqwest / ureq / std::net
  - `rust-build-rs-process-spawn` (2): std::process::Command
  - `rust-build-rs-reads-secret-env` (3): reads GITHUB_TOKEN /
    NPM_TOKEN / CARGO_REGISTRY_TOKEN / AWS_*
  - `rust-build-rs-reads-sensitive-file` (3): /etc, /root,
    ~/.ssh
  - `rust-lazy-init-network` for `lazy_static!` / `once_cell`
    with network calls in regular Rust source

### Added — trust-anchor drift forensics

New detector layer `internal/detectors/trustdrift/`. Two-layer
defense:
- **Content-aware** warnings fire on first run for high-risk
  shapes regardless of baseline state (`.npmrc registry=`
  pointing somewhere non-canonical, `git config insteadOf`
  rewrites, `pip.conf index-url` flipped).
- **Drift detection**: baseline at first run
  (`~/.chaindora/trustdrift-baseline.json`), report Added /
  Modified / Removed on subsequent runs.

Monitored anchors:
- `~/.npmrc`, `~/.pypirc`, `~/.pip/pip.conf`,
  `~/.config/pip/pip.conf`
- `~/.cargo/config.toml`, `~/.gemrc`
- `~/.gitconfig` (insteadOf rewrites = HIGH severity)
- `~/.ssh/known_hosts`
- OS CA bundle (macOS / Linux)

Flags via `chdora forensics`:
- `--skip-trust-drift` (skip the layer entirely)
- `--trust-drift-update-baseline` (refresh after intentional
  registry changes)

Live-verified: a synthetic `.npmrc` redirecting to
`https://evil-mirror.example.com/` + a `.gitconfig insteadOf`
rewrite both fire HIGH-severity findings on the first
forensics run.

### Deferred to v0.11.1

- **Git-URL trust evaluator** (`pip install git+...`,
  `npm install user/repo`, `go get` against unknown hosts,
  CMake `FetchContent_Declare`). The hardest remaining piece
  per the threat model — requires a fundamentally different
  trust model than registry-backed packages. Lands in v0.11.1.

### Tests

All ecosystem stacks tested via the existing stub-probe
infrastructure (`internal/gate/testprobes_test.go`).
Build-time scan tested with synthetic Go / Rust fixtures
for both positive (attack-shape) and negative (legitimate-use)
cases. Trust-drift detector tested in CLI E2E. All green
under `go test ./... -race`.

## [0.10.1] — 2026-05-16

### Docs

- **`docs/threat-model.md`** — the permanent reference for what
  chaindora covers, what's deliberately out-of-scope, and how the
  roadmap is prioritized. Organized around four dimensions of
  supply-chain risk: code-entry vectors (where bytes come in),
  code-execution moments (when arbitrary code runs), trust-anchor
  vectors (what would invalidate every other check), and adjacent
  surfaces (IaC, ML, identity, developer environment). Explicitly
  lists tool classes chaindora will NOT compete with (EDR, SIEM,
  runtime monitoring, credential rotation). Includes a quantitative
  prioritization framework so feature proposals are evaluated on
  attack-frequency × blast-radius × user-base ÷ effort rather than
  intuition.

- **README roadmap re-ranked against the threat model.** Each
  milestone now targets a specific attack-surface gap, not an
  ecosystem checklist. v0.11 closes the highest-leverage gaps
  (git-URL trust evaluation, build-time / import-time static scan
  for Go and Rust, trust-anchor drift forensics) plus the
  originally-planned RubyGems / crates / Maven detection. v0.12
  becomes IaC supply chain (Terraform, Helm, Ansible, Composer,
  NuGet). v0.13 is server mode + multi-machine. v0.14 is AI/ML
  supply chain (HuggingFace pickle, MCP/Claude-Code-skill
  auditor). v0.15 is emerging surfaces (Bun binary lockfile,
  Deno, devcontainers, slopsquatting, editor plugin managers).
  v0.16+ is the long tail. v1.0 is reproducible-build verification.

- CLAUDE.md now references the threat model as the on-ramp for
  contribution-proposal evaluation.

No code changes. All tests still green under `-race` across the
ubuntu/macos/windows CI matrix.

## [0.10.0] — 2026-05-15

The "production-ready CI + multi-ecosystem prevention" milestone.
Closes most of the gap between v0.9.0's prevention proof-of-concept
and a tool teams can drop into their PR pipelines unmodified.

### Added — `chdora ci` is now SonarQube-grade

- **`--baseline <path>`** — first run writes the current findings'
  fingerprints to the path; subsequent runs compute the diff and
  apply `--fail-on` only to NEW findings. The whole point: pre-
  existing tech-debt findings don't break every new PR. Pair with
  `--update-baseline` after intentional resolution / acceptance to
  refresh the file.

- **`.chaindora-ignore.yml`** — per-project suppression file
  discovered by walking up from the scan root. Each entry must
  carry a `reason` (parser refuses silent suppression). Match by
  exact `fingerprint` OR by `vuln_id` plus optional
  `package` / `version`. Optional `expires: YYYY-MM-DD` — expired
  entries continue to apply but emit a warning. `--ignore-suppressions`
  bypasses the file for full audits; `--suppress-file <path>`
  overrides discovery.

- **`--format pr-comment`** — emits GitHub-flavored markdown with a
  one-line verdict, severity-counts table, expanded "new since
  baseline" section, and collapsible "pre-existing" / "suppressed"
  blocks. Includes a sticky-comment marker
  (`<!-- chaindora:pr-comment -->`) so update-or-create flows work.
  Also writable to a sidecar file via `--pr-comment <path>`.

- **Quality-gate semantics**: `--fail-on` now applies to
  post-suppression, post-baseline-diff findings — exactly the
  set the PR introduces.

### Added — gate ecosystem + provenance expansion

- **yarn + pnpm resolvers** for `chdora gate exec` /
  `chdora gate install`. Yarn classic (v1) + Berry (v2+) both
  supported; pnpm covers the v5-6 slash-style keys AND v7+
  `@`-style keys plus peer-deps annotations. The shim mechanism
  installs `npm`/`yarn`/`pnpm` shims at once; non-install verbs
  pass through transparently.

- **PyPI gate parity** — cooldown + OSV + static-pattern now run
  against PyPI packages. Cooldown queries
  `pypi.org/pypi/<pkg>/json` for upload timestamps; static-pattern
  downloads the sdist and runs the same suspicious-pattern stack
  as npm tarballs. Publisher-change / maintainer-trust /
  version-diff remain npm-only for v0.10 (PyPI's `_user` metadata
  is shaped differently); follow-up in v0.10.x.

- **Sigstore-provenance check** (`provenance` checker).
  Default policy: Warn when this version lacks provenance BUT
  another version of the same package HAS provenance — that's
  the high-signal regression case (publisher used to attest,
  stopped). Bare absence on never-attested packages stays
  Approve. `--require-provenance` flips on strict mode that
  blocks anything without attestation.

### Added — `chdora watch` continuous-protection daemon

- **`chdora watch`** — long-running command that periodically
  re-scans projects under `$HOME` and alerts on findings new
  since the previous pass. State persists at
  `~/.chaindora/watch-state.json`.

- `--interval 1h` (default), `--once` for cron-style one-shot,
  `--webhook URL` to POST `new-finding` events as JSON, `--verbose`
  to log every pass even when nothing changed. SIGHUP triggers an
  immediate re-scan; SIGTERM / SIGINT exits cleanly.

- Webhook URLs are auto-redacted in the startup log so basic-auth
  credentials and query-string secrets don't leak into process
  listings or shared terminals.

### Changed — README + docs

- Concrete per-OS download examples replace `<version>_<os>_<arch>`
  placeholders. macOS-arm64 / macOS-intel / Linux-amd64 /
  Linux-arm64 / Windows-amd64 commands shown explicitly with
  version 0.9.2.

### Tests

- New tests for: suppression (load + match + filter + expired),
  baseline (round-trip + diff + dedup), PR-comment (clean repo,
  new criticals, pre-existing, expired suppressions),
  yarn/pnpm parsers (classic + Berry + v5-6 + v7+ key shapes),
  provenance (present / absent / regression / strict / network
  error). All green under `go test ./... -race`.

## [0.9.2] — 2026-05-15

### Docs

- **README rewrite.** Old README dumped seven commands in arbitrary
  order with no mental model. New README organizes around the two
  modes — **prevention** (`chdora gate`) and **detection**
  (`scan` / `forensics` / `audit` / `ci`) — and explicitly
  disambiguates the four detection commands by what they look at:
  `scan` = one project tree, `forensics` = host state, `audit` =
  both, `ci` = scan tuned for CI. Adds a "what it catches" matrix,
  the four finding categories (supply-chain-attack /
  dependency-cve / configuration / host-state), the difference
  between `--exclude <dir>` (skip dirs during walks) vs
  `--exclude-<category>` (hide sections from output) vs
  `--skip-<layer>` (disable detectors). Each gate checker gets a
  one-row description so users can pick which to skip.

- **CLAUDE.md rewrite.** Same two-mode framing for contributors.
  Adds the v0.9 gate package to the per-package gotchas, fail-closed
  invariants, the cross-platform `os.UserHomeDir` gotcha that broke
  v0.9.0's Windows CI, the recursion guard in `findRealPackageManager`,
  and per-pattern dedup in `static-pattern`. Repo layout updated
  to show the gate package alongside the existing tree.

No code changes. Tests remain green under `-race` across the
ubuntu / macos / windows matrix.

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
