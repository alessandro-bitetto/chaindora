# Architecture

Chaindora is a Go CLI (`cmd/chdora`) with an Angular static site (`website`).
Scanning and single-package checks cover npm, PyPI, NuGet, Go modules and crates.io.
The hardened install path in 0.0.4 covers frozen npm restores on macOS/Linux.
See the [command matrix](../README.md#gate-command-coverage).

## Detection

`internal/inventory.Scan` parses lockfiles and manifest fallbacks with shared
exclusions. Packages carry canonical registry identity, source paths and hashes.
For npm aliases, the registry name takes precedence over the installation alias.
OSV `MAL-` IDs are Critical even without CVSS or successful advisory hydration.

The CLI combines OSV, incidents, source heuristics and registry predictors.
Predictive Unknown results emit `CHDORA-PREDICTIVE-INCOMPLETE` configuration
findings. Missing, empty or invalid incident packs emit
`CHDORA-INCIDENTS-INCOMPLETE`; an explicit pack path never falls back to defaults.
Offline/skip-registry settings disable all registry heuristic requests, including
fresh-popular checks. Host persistence, credentials, trust anchors and browser/IDE extensions
remain separate detectors. These layers provide evidence, not runtime containment.

`internal/artifacts` verifies archive digests and constructs npm file manifests
without extracting or executing package code. The integrity detector compares
installed regular files with these manifests, including alias paths. Missing
cache entries, unsupported locks or failed verification produce
`CHDORA-INTEGRITY-INCOMPLETE`; offline mode never fetches artifacts.

CI treats inventory and these inspection failures as operational errors: JSON
and SARIF retain them, exit status is 2, suppressions/baselines cannot waive them,
and fixes/baseline updates do not run. Explicit skip flags reduce coverage.
CI validates severity-policy tokens before scanning. Suppression YAML uses known
fields and one document; dates are validated and expired exceptions do not apply.

## Frozen npm installation

1. Parse gate arguments and project configuration. Invalid YAML or unknown
   fields refuse the command. Unsupported commands refuse before binary lookup.
   Exact help/version arguments are the only uninspected handoff.
2. `PrepareNPMTransaction` obtains an exclusive project lock and recovers an
   interrupted transaction before reading the actual project's manifest and v2/v3
   lockfile. It validates paths and public-registry URLs, and rejects unsupported
   workspace/config/link cases. No resolver subprocess is started.
3. Download each locked artifact with bounded I/O or reuse its verified cache
   entry. Check the digest, archive paths and package name/version; retain a
   private immutable-by-convention snapshot in the staging directory.
4. Run current checks against canonical names and those snapshots. Integrity
   history and explicit deny rules take precedence over allow exceptions.
   Exceptions bypass signal checks, are not stored as ordinary approvals, and
   never bypass artifact/transaction verification.
5. If all packages satisfy policy, recheck manifest/lock/snapshot bytes. Seed a
   private npm cache, then run trusted npm offline with scripts disabled, empty
   user/global config and a restricted environment. No original command is replayed.
6. Compare npm's installed graph and the staged package files with the approved
   graph and verified manifests; verify npm did
   not rewrite the manifest/lock and that project inputs have not changed. Only
   then replace `node_modules`, retaining the previous tree until replacement
   succeeds. A write-ahead recovery journal records each transition.

The OS lock covers preparation through cleanup, survives in an inherited npm
descriptor if the CLI dies, and releases when all holders exit. The lock file is
never unlinked. Recovery journals live in private per-user storage under
`~/.chaindora/install-transactions`, keyed by the canonical project path; project
files cannot authorize recovery. The next transaction restores the previous
installation or completes an already-promoted verified tree. Cleanup is
restartable, and ambiguous states preserve data and refuse the operation.

The two renames are not a single atomic operation; recovery covers process
interruptions, not arbitrary storage corruption or full power-loss durability.
Direct package-manager commands do not participate in the lock. Concurrent edits
by a privileged local attacker are outside the trust boundary. Build hooks remain
disabled, so some packages will need a separately reviewed build.

`gate exec --dry-run` stops before invoking npm. `gate check` only evaluates a
single package; it never installs. Legacy `resolve_*.go` adapters remain tested
for future work but are not reachable from the install dispatcher. They are not
a sandbox and must not be re-enabled without artifact/graph binding.

## Source inspection

Archive readers cap downloads and decoded streams at 50 MiB, individual files at
4 MiB, entries at 10,000 and nested payload depth at three. Frozen transactions
also cap unique compressed artifacts at 512 MiB. Failures produce Unknown or
refusal, never successful inspection. Supplied SRI, SHA-256 hex and Go h1 hashes
are verified before scanning; unsupported representations are explicit failures.
A package check without a lock digest does not authenticate a project artifact.

JS/TS, Python credential collection, Go init and Rust build/source rules are
heuristics. Scores deduplicate pattern names; version-diff compares source
signals across releases. Provenance metadata does not authenticate signatures.

## Fleet service

The listener defaults to `127.0.0.1:8080`. Dashboard/API reads require a separate
operator credential: Bearer authentication or browser Basic authentication with
username `viewer`. The CLI generates a private `read-token` file in its data
directory, or loads `--read-token-file`. Only health/version reads are public.
Enrollment is disabled without a secret. Enrolled agents use per-agent write
credentials; these cannot read fleet data. Upload/enrollment bodies are bounded.
Terminate TLS in a reverse proxy before exposing the service remotely.

## Shims and repository map

`gate install` writes managed wrappers under `~/.chaindora/bin` on macOS/Linux.
All 15 names remain to provide explicit refusal; keeping a shim does not imply
an install adapter. Binary lookup excludes shim paths and marker signatures.
Cleanup removes only regular managed files. Windows scanning is supported;
Windows frozen installs and automatic wrappers are not currently supported.

| Path | Responsibility |
|---|---|
| `cmd/chdora`, `internal/cli` | Commands, policy orchestration and output |
| `internal/inventory` | Lockfile/manifests and shared CI references |
| `internal/artifacts` | Verified archive cache, hashes and file manifests |
| `internal/gate` | Frozen transaction, signal checks and integrity history |
| `internal/detectors`, `internal/registries`, `internal/osv` | Detection and evidence |
| `internal/findings`, `internal/fixplan` | Reports and remediation plans |
| `internal/server` | Authenticated optional fleet service |
| `incidents`, `testdata`, `tests` | Intelligence, inert fixtures and contracts |
| `website` | Angular static site |

See the [threat model](threat-model.md) and [hardening assessment](security-hardening.md).
