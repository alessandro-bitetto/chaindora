# Changelog

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
