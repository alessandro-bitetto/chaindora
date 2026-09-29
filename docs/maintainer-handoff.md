# Maintainer guide

Chaindora 0.0.1 consists of a Go CLI, curated incident data and an Angular
static website. Start with the [README](../README.md),
[architecture](architecture.md) and [threat model](threat-model.md).

## Release workflow

Run the Go race tests and vet checks, then build the website. The GitHub test
workflow validates Linux, macOS and Windows. Update the CLI default version,
website package metadata, source-install examples and changelog together.

A `v*` tag triggers `.github/workflows/release.yml`. GoReleaser builds `chdora`
for Linux/macOS/Windows on amd64 and arm64, packages the binary with the license,
documentation and incident pack, and publishes SHA-256 checksums. Archive names
use `x86_64` for amd64. Version 0.0.1 is tagged `v0.0.1`.

The workflow uses the repository-scoped `GITHUB_TOKEN` with contents-write
permission. No GPG signature is configured; do not describe checksum files as
signed. Verify uploaded assets, the release page and a downloaded native binary
before considering publication complete. Commit and publish only when authorized.

## Website

`website/wrangler.toml` configures Cloudflare static assets from `dist/browser`.
Build with `npm ci` and `npm run build` in `website/`. GitHub does not currently
provide a Pages workflow in this repository. Hosting credentials and deployment
access are separate from the CLI release token; never commit them. The generated
Infrar build specifications remain available under `.infrar` directories.

## Services and state

| Dependency | Purpose |
|---|---|
| GitHub | Source, CI, releases, incident updates and optional URL evidence |
| OSV | Vulnerability and malicious-package data |
| npm, PyPI, NuGet, crates.io, Go proxy | Registry metadata and artifact inspection |
| Cloudflare | Static website hosting configuration |

The CLI requires no daemon or database server. Optional fleet mode uses local
JSON storage and should sit behind a TLS-terminating proxy with enrollment
protection configured. There is no telemetry.

Per-user `~/.chaindora` state includes gate integrity history, registry cache,
incident data, saved plans, shims and optional agent/server data. Losing integrity
history loses historical comparisons. Agent credentials and reports require
appropriate access controls and backups.

## Maintenance rules

- Preserve fail-closed gate behavior, resource budgets and independent policy
  overrides. Treat unknown coverage explicitly.
- Keep the five-ecosystem inventory, gate mappings and documentation aligned.
- Use authoritative references for incident entries and inert test fixtures.
- Keep JSON stdout free of progress output; diagnostics go to stderr.
- Changes to finding fields must keep the documented JSON schema consistent.
- Never imply full mediation, sandboxing or cryptographic provenance validation
  where the implementation only supplies heuristic or metadata evidence.

Security reports: [SECURITY.md](../SECURITY.md). General work:
[GitHub issues](https://github.com/alessandro-bitetto/chaindora/issues).
