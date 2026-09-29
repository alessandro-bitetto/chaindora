# Chaindora documentation

Documentation for **Chaindora 0.0.1**. The executable is `chdora`.

Start with a project scan, review the evidence, then add install policy and CI
checks where they fit your workflow.

## Use Chaindora

| Task | Guide |
|---|---|
| Download, verify and install | [Installation](installation.md) |
| Check supported ecosystems, managers and lockfiles | [Supported scope](../README.md#supported-scope) |
| Scan projects and investigate findings | [Detection and investigation](../README.md#detection-and-investigation) |
| Configure the install gate | [Prevention](../README.md#prevention) |
| Add a CI check, baseline or suppression | [CI integration](ci-integration.md) |
| Resolve installation, gate or reporting problems | [Troubleshooting](troubleshooting.md) |

## Understand the results

| Topic | Reference |
|---|---|
| What Chaindora can and cannot protect | [Threat model](threat-model.md) |
| Detection pipeline, gate checks and repository layout | [Architecture](architecture.md) |
| Remaining security work and acceptance criteria | [Security roadmap](security-hardening.md) |
| Real package-manager validation, findings and safe test runner | [Environment testing](environment-testing.md) |
| Finding fields | [Finding JSON schema](schema/v1/finding.schema.json) |
| Fleet scan completion metadata | [Scan summary JSON schema](schema/v1/scan-summary.schema.json) |

`--format json` emits findings, not a dependency inventory or scan-summary
envelope. The scan-summary schema describes fleet metadata; it does not imply
that every CLI output includes a completion record. A successful scan can still
have unsupported, skipped or incomplete checks. Read the threat model before
using a result as an enforcement decision.

## Contribute and maintain

- [Contributing](../CONTRIBUTING.md)
- [Incident-pack guide](incident-pack.md) and [incident schema](../incidents/SCHEMA.md)
- [Maintainer guide](maintainer-handoff.md)
- [Website development](../website/README.md)
- [Security reporting](../SECURITY.md)
- [Changelog](../CHANGELOG.md)

[Website](https://chaindora.dev) ·
[Download 0.0.1](https://github.com/alessandro-bitetto/chaindora/releases/tag/v0.0.1) ·
[Report a bug](https://github.com/alessandro-bitetto/chaindora/issues)
