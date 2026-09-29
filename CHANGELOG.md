# Changelog

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
