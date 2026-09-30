# Threat model

This document describes the controls in 0.0.4. Version 0.0.3 and earlier do not
have all of these protections.

## Scope and trust

Chaindora scans npm, PyPI, NuGet, Go modules and crates.io, plus CI references
and selected host evidence. Its install boundary currently accepts only frozen
public-registry npm restores on macOS/Linux. Other commands refuse except exact
help/version requests. Windows scanning and package checks remain available.

An attacker may publish a malicious dependency, change registry bytes, disguise
a package behind an alias, or modify an installed file. The local OS, package
manager executable, operator policy and reviewed lockfile are trusted. A local
attacker with the same user's privileges can alter policy/history or bypass PATH
shims; Chaindora does not enforce an OS security boundary.

## Existing controls and limits

| Surface | Control | Limit |
|---|---|---|
| Known malware | OSV MAL hits are Critical without requiring CVSS; incident packs match canonical npm alias identities | Intelligence lag, unavailable feeds and inventory gaps |
| Frozen npm restore | Lock graph, hash-verified artifact snapshots, script-disabled offline staging and installed-file comparison | Only public-registry v2/v3 npm locks; no workspace/local/git or custom-config transactions |
| Registry substitution | Artifact hashes verified before source inspection and installation; cache revalidated on read | A matching hash authenticates locked bytes, not publisher intent or safety |
| Installed modification | npm published files compared against verified archive manifests; missing/extra/changed paths reported | Generated/native outputs may differ legitimately; other ecosystems lack equivalent byte verification |
| Metadata/source signals | Cooldown, publisher history, JS/TS/Python credential shapes, Go/Rust source patterns | Heuristics can miss attacks and flag legitimate behavior; bytecode/data flow not comprehensively analyzed |
| Changed release content | Persistent integrity history | Hash/platform differences require review; local history is mutable |
| Provenance | Available registry metadata | Presence alone is not signature, subject-digest or builder-identity verification |
| Fleet data | Independent operator read credential; per-agent writes; disabled unauthenticated enrollment; loopback default | Remote deployment still needs TLS and protected storage |
| Host compromise | Persistence, credential, trust-anchor and extension evidence | Snapshot investigation, not continuous EDR or containment |

## Install boundary

The gate reads the actual manifest/lock and fetches artifacts without invoking
resolvers. It rejects missing hashes, unsafe paths, archive links and unsupported
configurations. An accepted transaction uses only private inspected snapshots,
then invokes trusted npm with an isolated cache, empty user/global config,
restricted environment, offline mode and lifecycle scripts disabled. It rechecks
inputs and staged files before replacing `node_modules`.

The original command is never replayed. Bare `npm install` behaves as a frozen
restore and cannot change versions. Additions, updates, workspaces, non-npm
installs and arbitrary run/build commands refuse before package-manager execution.
Lockfile generation and later builds outside this route remain outside protection.
Dry-run performs downloads and policy checks but starts no package manager.

There is no process sandbox. Packages needing generated/native outputs may not
work without a separate reviewed build. An OS lock serializes gated transactions;
a surviving npm child retains it after the CLI exits. A private per-user journal
allows the next transaction to recover process interruptions around the directory
swap. Project-controlled journals are ignored, and ambiguous recovery preserves
the staged and previous data. The swap is not crash-atomic and does not guarantee
full power-loss durability. Direct manager commands bypass the cooperative lock;
concurrent privileged tampering remains outside scope.

## Policy and failed inspection

Strict policy refuses Block, Warn and Unknown. `--lenient` permits Warn;
`--allow-offline` permits Unknown but does not disable networking. Neither
relaxes artifact identity, digests, supported transaction shape or file checks.
Explicit allow entries bypass signal checks, with deny and changed-integrity
history taking precedence. Exceptions are not saved as normal approvals.
Malformed YAML and unknown configuration fields are errors, never defaults.
CI rejects invalid severity-policy tokens and suppression dates. Expired
exceptions stop suppressing after their specified UTC calendar day.

Cache history never authorizes a fresh install by itself. Registry service
caches do not guarantee immediate advisory freshness. Some registry checks are
not applicable or only supply project-level metadata; an approval is not evidence
of equivalent coverage across all five registries.

Predictive Unknowns are visible as `CHDORA-PREDICTIVE-INCOMPLETE`. Installed-file
verification failures use `CHDORA-INTEGRITY-INCOMPLETE`; failed inventory uses
`CHDORA-INVENTORY-INCOMPLETE`. Missing, empty or malformed incident packs use
`CHDORA-INCIDENTS-INCOMPLETE`. CI reports these and exits 2 regardless of severity,
suppressions or baselines, without applying fixes or updating a baseline.
Explicit offline/skip flags reduce requested coverage. Offline and skip-registry
override fresh-popular registry requests. An uninstalled project
has no installed files to verify. A clean run does not establish attack absence.

## Resource and privacy boundaries

Archive limits: 50 MiB downloaded/decoded, 4 MiB per file, 10,000 entries, depth
three for nested source inspection. Frozen transactions cap compressed unique
artifacts at 512 MiB. Legitimate large archives can be refused. File readers do
not traverse symlinked paths inside an npm installation. Offline npm verification
needs previously verified artifacts in `~/.chaindora/artifacts`.

There is no telemetry. Online checks disclose queried package identities to
OSV/registries. Fleet reporting is opt-in, but findings can contain sensitive
paths and evidence. Protect token files, saved reports, caches and fleet state.
Only health/version fleet reads are unauthenticated; dashboard/API credentials
must travel over TLS whenever the service is used beyond localhost.

See [completed fixes and remaining work](security-hardening.md). Synthetic
regressions establish specific behavior, not real-world recall or false-positive rates.
