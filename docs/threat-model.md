# Threat model

Chaindora provides install-time policy checks and investigation signals for
npm, PyPI, .NET/NuGet, Go modules and Rust/crates.io. Alternative managers remain
within those ecosystems. Shared CI/container-reference and host checks remain.
Other dependency registries are outside the supported scope.

## Attacker and protected assets

An attacker may publish a malicious package, compromise a maintainer account,
change dependency resolution, swap registry content, introduce an unsafe CI
reference, or persist after an install. Assets at risk include source code,
package-publishing tokens, cloud credentials, SSH material, build outputs and
the developer or CI account's execution privileges.

The package manager, local OS and Chaindora binary are assumed to be under the
operator's control. A privileged attacker can bypass PATH shims, rewrite local
policy/history or tamper with the scanner. Chaindora does not enforce an OS
security boundary.

## Existing controls and limits

| Attack surface | Current evidence/control | Material limit |
|---|---|---|
| Known malicious packages | OSV MAL entries and curated incident evidence | Intelligence lag and incomplete inventory; the gate blocks MAL hits and warns on CVEs |
| Fresh release or publisher change | Cooldown, publisher and maintainer checks | Age/popularity are not safety; metadata is absent or project-level in some registries |
| Suspicious package code | JS/TS patterns, Python credential-collection shapes, Go init and Rust build/source patterns | Regex heuristics; evasion, false positives, no full data flow or bytecode coverage |
| Changed release content | Integrity history and republish alerts | Compares available integrity strings; platform variants/hash representations need investigation |
| Installed modification | Name/version and lockfile integrity metadata drift | Does not verify every installed file against a trusted artifact manifest |
| Build provenance | Available registry provenance signals | Presence is not signature, identity or digest verification |
| CI and container references | Pinning, drift and incident heuristics | Not full workflow execution analysis or image scanning |
| Host compromise | Persistence, trust-anchor, credential and extension checks | Snapshot evidence; not continuous EDR or runtime containment |

## Install boundary

The command dispatcher only mediates selected forms. Bare `npm install`,
`npm ci`, `uv pip install`, restore/build/run paths and unrecognized verbs can
pass through. Alternative-manager support is retained, but is not a claim that
every current manager version, workspace or install form is covered. Deno's
existing-state resolver and Paket's lockfile-only resolver do not model all
requested changes. Deno raw HTTPS/JSR imports are outside the registry scope.
Automatic Windows wrapper installation is incomplete; use explicit `gate exec`
commands there. See [command coverage](../README.md#gate-command-coverage).

Resolution invokes external package managers. Dry-run, lockfile-only and
ignore-script options do not constitute a sandbox. Python source metadata/build
hooks and package-manager plugins or overrides can execute before approval.
Even `gate exec --dry-run` runs the resolver. Do not expose valuable secrets to
an untrusted resolution process on the assumption that the gate isolates it.

After approval, the original command runs in the actual project with the user's
privileges. Its graph, configuration, registry responses or artifact bytes may
differ from those checked in a temporary project. Artifact inspection fetches
registry content without yet binding it to the resolved integrity value.
Exact transaction binding and isolated resolution are the highest-priority gaps.

## Failures and policy

Strict gate policy refuses Block, Warn and Unknown. `--lenient` only permits
Warn; `--allow-offline` separately permits Unknown and does not turn networking
off. Block wins over both. Explicit allowlist entries bypass checks. Some
checkers return Approve for unsupported signals, so approval is not proof that
every check applied. Network and archive failures in implemented checks must
not be represented as successful inspection.

Current checks rerun for each gate invocation. Cached approvals are integrity
history, not install authorization. Registry clients can cache service data;
this does not guarantee immediate advisory freshness. History can be cleared or
changed by the local user. It is not a signed transparency log.

Detection is best-effort. Offline and skip flags reduce coverage. Credential
inspection failure emits a Low configuration finding; most other predictive
Unknown results are suppressed. CI severity thresholds alone cannot enforce a
minimum inspection-coverage requirement. No findings does not mean no attack.

## Resource and privacy boundaries

Archive inspection caps downloads/decoded streams at 50 MiB, files at 4 MiB,
entries at 10,000 and nested payload depth at three. Exceeding limits produces
Unknown, including for legitimate large artifacts. Parsing succeeds without
proving all contained languages or executable formats were understood.

There is no telemetry. Network checks send package identities to registry/OSV
services. Artifact downloads expose ordinary network request metadata. Fleet
reporting sends findings only through the configured, opt-in workflow. Finding
output can contain sensitive paths and incident evidence; protect reports as
part of the project's security data.

## Priorities

1. Bind resolution, inspected digests and executed installation into one frozen
   transaction, including transitive dependencies and platform artifacts.
2. Isolate or refuse unsafe resolution and execution of install/build hooks.
3. Cover common install/restore paths and explicitly report unsupported routes.
4. Verify installed file contents and authenticate provenance.
5. Report checked/failed/skipped coverage separately from findings; measure
   detection against inert attack replays and benign controls.

The [hardening assessment](security-hardening.md) includes code-level evidence
and acceptance tests. New ecosystem names are lower priority than establishing
these properties for the five supported ecosystems.
