# Changelog

## [0.0.4] — 2026-09-30

**Breaking:** gated installs now accept only frozen public-registry npm restores
on macOS/Linux. Other ecosystems retain scanning and package checks. Fleet
dashboard/API reads require a separate operator credential. CI now refuses
missing incident packs and expired exceptions no longer hide findings.

- Bind accepted npm restores to the actual lockfile, verified artifact snapshots,
  offline script-disabled staging and final file/input checks. Refuse unsupported
  commands before execution; other managers retain scan/package-check support.
- Make OSV MAL severity independent of CVSS and preserve npm alias identities.
- Fail on malformed gate policy; make explicit allow/deny overrides deterministic
  while retaining artifact checks and changed-integrity history.
- Authenticate fleet reads independently from agent enrollment; default to loopback
  and disable enrollment until a secret is configured.
- Verify installed npm files against authenticated archives; make missing evidence
  and predictive failures visible, unsuppressible CI operational failures.
- Select PyPI artifacts by the locked digest and verify Go module h1 hashes.
- Honor explicit CI suppression-file paths without directory discovery.
- Reject invalid CI severity policies, malformed suppression YAML and invalid
  expiry dates; expired exceptions no longer suppress findings.
- Make offline/skip-registry override fresh-popular network requests.
- Report missing, empty and malformed incident packs as incomplete inspection;
  CI exits 2 regardless of severity overrides, suppressions or baselines.
- Lock frozen npm transactions through cleanup, retain the lock in surviving
  children, and recover interrupted swaps from private per-user journals.
- Add artifact, policy, authentication, offline CLI and real npm regressions.

## [0.0.3] — 2026-09-30

- Explain upgrade permission failures with the affected installation directory
  and guidance for administrator or user-writable installations.
- Print command errors once and keep silent exit codes free of error messages.
- Document upgrades for manually installed binaries in `/usr/local/bin`.
- Add regression tests for protected installation directories, preserving the
  installed binary on failure, and generic, typed and silent CLI exits.

## [0.0.2] — 2026-09-29

Fix install-gate and inventory failures found by the expanded environment tests.

- Select script-disabled Yarn Classic or Berry resolution before installing any
  dependency; reject flags that override the resolution mode or script policy.
- Refuse empty dependency graphs, preserve Deno subprocess failures, and prevent
  dry-run commands from handing off to package managers.
- Report incomplete CI inventory in JSON/SARIF and exit 2 regardless of severity,
  suppression or baseline settings; leave baselines and fixes untouched.
- Correct Bun resolution, Deno v3–v5 npm inventory, Paket dependency records,
  uv/Berry project-root filtering and exact PyPI manifest pins.
- Add harmless fixture tests for all 15 manager names, both Yarn variants and
  lifecycle suppression, with offline container execution and retained evidence.
- Verify Go race tests and CLI contracts on Linux, macOS and Windows; validate
  the full real-manager matrix on Linux arm64 and amd64.

See [environment validation](docs/environment-testing.md) for results and limits.

## [0.0.1] — 2026-09-29

Initial release of Chaindora: supply-chain prevention and detection for npm,
PyPI, .NET/NuGet, Go modules and Rust/crates.io.

- Fifteen package-manager executable names, including Yarn, pnpm, Bun, Deno, Poetry,
  uv, Pipenv, PDM and Paket. Command coverage is documented in the README.
- Install-time checks for known malicious packages, release age, publisher and
  maintainer signals, source patterns, version differences and project policy.
- Project and host scanning, incident evidence, integrity metadata checks,
  credential-collection heuristics and CI reporting with JSON/SARIF.
- Strict handling of incomplete checks, bounded archive inspection, and
  integrity history that never substitutes for current policy checks.
- Optional fleet reporting and reviewable remediation plans.
- Responsive landing page with working installation navigation and command copying.
- Release archives and SHA-256 checksums for macOS, Linux and Windows on
  x86_64 and arm64.

Read the [threat model](docs/threat-model.md) for protection boundaries and the
[security roadmap](docs/security-hardening.md) for remaining work.
