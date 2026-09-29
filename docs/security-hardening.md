# Security controls and roadmap

Chaindora 0.0.1 focuses on strengthening the install boundary and the evidence
behind detection in npm, PyPI, NuGet, Go modules and crates.io. Alternative
managers are supported within that scope. The [README](../README.md#supported-scope)
lists exact command and inventory coverage.

## Current controls

| Control | Behavior |
|---|---|
| Current policy evaluation | `CachedRun` always executes the requested checker stack. Integrity history cannot authorize an install by itself. Registry clients have separate service-data caches. |
| Independent verdict policy | Block always refuses. Warning and Unknown results each require their own override; empty evidence is Unknown. |
| Persistent integrity evidence | Hash history survives approval TTL until cleared. Concurrent writes use unique temporary files. Integrity differences require review of artifact/platform identity. |
| Bounded archive inspection | Downloads, decoded streams, individual files, entries and nesting have limits. Truncation, corruption, trailing payloads and exhausted limits are incomplete inspection, not approval. |
| Credential-collection detection | JS/TS and Python rules combine collection and outbound HTTP in the same file. Dedicated npm/PyPI predictive checks run independently of version differences. |

The named signatures are `env-var-exfil-shape` and
`credential-file-exfil-shape`. Each contributes weight 3 to the gate's static
score. Predictive findings use High severity and Medium confidence, and can
therefore fail the default CI severity policy. They identify suspicious
combinations for review, not proven exfiltration: no AST or interprocedural
data-flow analysis is performed. Single environment-variable reads, network
calls without collection, and credential-file reads without network calls
do not trigger these rules. Source snippets are not included in their evidence.

Predictive credential inspection downloads the registry artifact chosen by
the existing probe; it does not inspect the installed copy or every wheel for
every platform. Failed inspection emits a Low configuration finding instead
of disappearing. Existing offline/skip-registry/skip-predictive options still
disable this network-backed inspection. Other predictive checks retain their
existing treatment of Unknown results.

Archive defaults are 50 MiB per download and decoded tar stream, 4 MiB per
file, 10,000 entries, and three nested payload levels. Content and
entry budgets are shared across nested payloads. Legitimate large artifacts
can now produce Unknown and stop a strict/lenient install. Unsupported source
languages, bytecode and binaries are not semantically inspected. A successfully
parsed archive is not a clean bill of health.

The additional scans and removal of approval reuse increase work. A future
performance cache should retain artifact bytes or explicitly versioned
analysis results, while always reevaluating policy and current intelligence.
It must include the artifact, analysis version, requested checks, and relevant
configuration in its identity; historical verdicts alone are insufficient.

Republish history uses the existing `(ecosystem, name, version)` identity and
compares recorded integrity strings. Different platform artifacts or hash
representations can legitimately differ; the alert needs investigation. Artifact
identity and digest normalization should accompany the transaction work below.

## Priorities and acceptance tests

These gaps remain open. The suggested acceptance tests define what “done”
would mean; this change does not claim to implement them.

| Priority | Work | Evidence in current code | Acceptance test |
|---|---|---|---|
| P0 | Bind approval to the exact install transaction | `ResolveNPMTree` resolves in a synthetic project; `gate_exec.go` later executes the original arguments in the real project. `StaticScan` asks registry probes for bytes rather than verifying them against `PackageRef.Integrity`. | Swap a registry response, range resolution, mirror, project manifest or lockfile between resolution and execution. Installation must refuse, or consume only the already verified, content-addressed artifacts and frozen resolution. Include transitive dependencies, workspaces and platform artifacts; distinct legitimate wheels must not be mislabeled as republishes. |
| P0 | Prevent code execution during resolution | `ResolvePipTree` uses dry-run/report without a wheel-only restriction. Resolver flags are not a process sandbox. | Malicious metadata/build hooks, project plugins and user overrides cannot create a marker file, read an injected canary secret, or contact an unapproved endpoint before a verdict. Unsafe resolution must be isolated or refused explicitly. |
| P0 | Cover common install paths and make unsupported paths explicit | `classifyGateArgs` passes bare `npm install` through; `npm ci` is not an install verb. Flags before verbs, aliases, local/git dependencies and resolver flag overrides need systematic adversarial coverage. | Every documented install/restore/update route either gates the actual tree or emits an explicit unsupported/refused result. Test with a fake package manager and hostile args/config; no unreviewed install is silently forwarded. |
| P1 | Separate fetching from execution | After approval, `execReal` receives the original package-manager arguments. Install hooks inherit the user's process context. | Default restricted installs suppress hooks. Explicit build permission executes in an isolated environment with bounded filesystem/network access and a minimal secret-free environment. Native builds remain usable through a documented, narrow exception mechanism. |
| P1 | Verify installed file contents | `lockdrift.go` compares package name/version and lockfile mirror integrity. It explicitly leaves file-content recomputation as future work. | Modify a dependency's `index.js` while leaving both lockfiles and `package.json` unchanged. Detection must report the exact changed path against a verified artifact manifest. Model legitimate generated/native-build outputs separately. |
| P1 | Cryptographically verify provenance | npm `HasProvenance` checks registry metadata for attestation presence. Presence alone does not authenticate the artifact or builder. | Reject an invalid signature, wrong artifact digest, unexpected repository/workflow identity, or untrusted issuer. A syntactically present attestation must not pass these cases. |
| P1 | Make coverage measurable | Several unsupported probes return Approve; most predictive Unknown results are suppressed. “No findings” does not mean all packages were inspected. | Machine-readable reports distinguish checked, unsupported, failed and skipped packages/checks. CI can require a minimum coverage policy independently of finding severity. |
| P2 | Build an incident replay and benign-control corpus | Current tests cover individual mechanisms, but source heuristics cannot establish real-world recall or false-positive rates. | Versioned, inert fixtures for known attack shapes and representative legitimate tooling; publish per-rule detection/false-positive results and latency/resource costs. Expand based on measured misses. |
| P2 | Fleet containment and authenticated incident updates | Fleet aggregation exists, but shared observations are useful only when they can lead to narrowly scoped action. | Reviewed/signed incident updates, package/digest-specific deny rules, affected-install reporting and reversible quarantine plans. Treat age/popularity as supporting evidence, never a substitute for artifact verification. |

For safe package-manager semantics, consult the primary documentation:
[pip secure installs](https://pip.pypa.io/en/latest/topics/secure-installs/)
describes source-distribution code execution and wheel-only/hash-checked
installs; [pip install](https://pip.pypa.io/en/latest/cli/pip_install/)
describes dry-run/report behavior;
[npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
documents frozen lockfile installation and `ignore-scripts`. These options
are useful components of a design, not equivalent to sandboxing.

## Validation

Regression tests cover mixed verdict policies, current-stack evaluation, expired
integrity history, concurrent stores, malformed and oversized archives, checksum
failures, hidden trailing payloads, nested archive budgets, benign credential
controls and detection of unchanged suspicious behavior.

Scope tests cover supported managers, unsupported argument/manager refusal,
project discovery, ignored inventory formats and safe shim cleanup. Fixtures
use local HTTP servers and inert source; no malicious payload is executed.

Run `go test ./... -race -count=1`, `go vet ./...`, native and cross-platform
builds, and `npm run build` in `website/`. Browser checks should exercise
installation navigation, repeated fragment links, mobile menu, keyboard tabs,
CLI mode switching and command copying at desktop and narrow widths.
