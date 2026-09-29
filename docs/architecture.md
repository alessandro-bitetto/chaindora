# Architecture

Chaindora is a Go CLI (`cmd/chdora`) with an Angular static landing page
(`website`). The maintained dependency scope is npm, PyPI, NuGet, Go modules
and crates.io. See the [exact inventory and command matrix](../README.md#supported-scope).

## Detection pipeline

`internal/inventory.Scan` walks a project, applies shared directory exclusions,
and parses supported lockfiles and manifest fallbacks. Packages carry identity,
source path and integrity evidence when available. Python and .NET manifest
fallbacks yield to nearby lockfiles. CI/container references use separate
inventory categories, not additional dependency registries.

`internal/cli/scanprojects.go` runs OSV, incident, heuristic and predictive
layers and discovers project roots for audit/forensics. Discovery recognizes
alternative lockfiles and .NET project suffixes. Predictive detection reuses
gate registry probes and behavioral checks. Dedicated npm/PyPI credential
inspection runs independently from version-diff and emits an explicit Low
finding if inspection fails. Other predictive Unknown results retain their
existing, often silent treatment.

`internal/detectors` includes host persistence, trust-anchor, credential,
browser/IDE extension and integrity metadata checks. Host-level OS package
enumeration stays separate from dependency gate support. `internal/findings`
provides shared evidence, severity, confidence, categories and fingerprints.
JSON/SARIF and CI policies consume those findings. The optional server/agent
path stores and aggregates explicitly submitted fleet reports.

## Gate pipeline

1. `internal/cli/gate_exec.go` recognizes one of 15 managers and classifies the
   command. Unsupported managers are refused before binary lookup. Some forms
   of supported-manager commands pass through; see the README matrix.
2. A resolver in `internal/gate/resolve_*.go` uses package-manager output or
   project lock state to construct `PackageRef` values. Many paths use a
   temporary synthetic project; update-all variants copy project state.
   Deno and Paket are special existing-project paths with limited coverage.
3. `buildGateProbes` supplies only npm, PyPI, NuGet, Go and crates registry
   clients. `buildCheckerStack` assembles policy, cooldown, known-malicious OSV,
   publisher, maintainer, source, version-diff, provenance and git URL checks.
4. `CachedRun` checks integrity history, runs the current stack with bounded
   concurrency, and records eligible approvals. Historical approvals never
   authorize a new install by themselves. Hash history survives approval TTL.
5. `Policy.Decide` evaluates every result independently. Block always refuses;
   warning and unknown overrides are separate. Empty evidence is Unknown.
6. Only after policy approval does `execReal` invoke the original command.
   That invocation can resolve different bytes: transaction binding is open work.

`gate check` assesses one package. `gate exec --dry-run` resolves and reports
without handing off the install; it is not a sandbox for resolver subprocesses.
Gate flags precede the manager name; the rest belong to the manager.

## Archive and source inspection

`archive.go` bounds downloaded and decoded bytes, individual files, entries and
nested payloads. Malformed/truncated archives, checksum errors, hidden trailing
payloads and exhausted budgets produce errors, mapped to Unknown. Archive
support is a shared reader for tar/gzip/ZIP, independent of registry support.

`static.go` scans JS/TS patterns, Go initialization and Rust build/source shapes.
`credential_patterns.go` adds JS/TS and Python collection-plus-HTTP signatures.
Scores deduplicate pattern names rather than multiplying repeated occurrences.
`versiondiff.go` compares pattern counts across registry versions. These are
heuristics, not AST/data-flow analysis or executable/bytecode emulation.

## Shims and cleanup

`gate install` writes per-user wrappers under `~/.chaindora/bin` and optionally
a marked PATH block in shell configuration. The binary lookup excludes shim
directories and content-sniffs the shim marker to avoid recursion.
`gate_retired.go` removes regular files carrying the Chaindora shim marker when
their manager is outside the supported scope; it preserves supported shims during
installation, and ignores symlinks, directories and unmarked user files.
`gate disable` uses the same ownership check for removal.

## Repository map

| Path | Responsibility |
|---|---|
| `cmd/chdora`, `internal/cli` | Commands, orchestration, exit codes, reporting |
| `internal/inventory` | Five-ecosystem dependency inventory and shared CI references |
| `internal/registries`, `internal/osv` | Network evidence and service caching |
| `internal/gate` | Install resolution, checks, policy and integrity history |
| `internal/detectors` | Project and host detection |
| `internal/findings`, `internal/fixplan` | Evidence and reviewable remediation plans |
| `incidents`, `testdata` | Curated intelligence and inert fixtures |
| `website` | Static Angular landing page |

The [threat model](threat-model.md) defines boundaries. The
[hardening assessment](security-hardening.md) records remaining gaps and
acceptance tests. Read those before interpreting a successful scan or gate
approval as complete inspection.
