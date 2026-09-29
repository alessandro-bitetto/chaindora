# Contributing to the incident pack

[Documentation](README.md) · [Incident schema](../incidents/SCHEMA.md)

The curated YAML files in [`incidents/`](../incidents/) describe package/version
matches, file artifacts and incident-specific investigation steps. They
complement OSV advisory queries and source heuristics.

## Scope and data sources

Online OSV checks query supported inventory identities and classify returned
`MAL-*` advisories as malicious-package evidence. This depends on inventory
coverage, advisory data and successful queries; it is not coverage of every
entry in the OSV database.

Before adding a package-only incident, check whether OSV already supplies that
match. An entry can still be useful for additional file artifacts or investigation
steps. `chdora update` downloads this repository's curated pack; it does not
refresh OSV. The two data sources are independent.

Dependency package rules should target npm, PyPI, NuGet, Go or crates.io. Shared
CI and host evidence can use the corresponding inventory labels. An OS or browser
incident does not imply install-gate support for that ecosystem.

## Pack contents

| Incident file | Evidence described |
|---|---|
| [colors-faker-sabotage-2022.yaml](../incidents/colors-faker-sabotage-2022.yaml) | npm sabotage |
| [great-suspender-2021.yaml](../incidents/great-suspender-2021.yaml) | Browser-extension takeover |
| [pypi-typosquats-2019.yaml](../incidents/pypi-typosquats-2019.yaml) | Malicious Python package names |
| [qix-compromise-2025.yaml](../incidents/qix-compromise-2025.yaml) | Compromised npm package versions |
| [shai-hulud-2025.yaml](../incidents/shai-hulud-2025.yaml) | npm package matches and worm file artifacts |
| [xz-utils-cve-2024-3094.yaml](../incidents/xz-utils-cve-2024-3094.yaml) | Host/package indicators for xz-utils |

The matching detectors only emit evidence they can inventory or find on disk.
An entry's presence does not establish complete detection of that incident.

## Author an entry

Copy the template from [the schema](../incidents/SCHEMA.md) into a new YAML file.
Keep one incident per file, with a stable ID and at least one authoritative
reference. Each entry can supply:

- `packages`: ecosystem, exact name and affected version strings. Use `"*"`
  only when every version of the namespace is malicious. Semver ranges are not
  interpreted by this matcher.
- `file_artifacts`: conservative relative-path globs, optionally narrowed by
  `content_substr`. Include the artifact's severity and an explanation.
- `safe_version`: an explicitly supported remediation target from the source
  advisory, where available.
- `post_compromise`: manual investigation and credential-response steps.

Package matches use the entry's configured severity; file matches use the
artifact's configured severity. Do not label every match Critical automatically.
Avoid speculative claims or signatures that also match common legitimate files.
Remediation advice must distinguish a dependency update from responding to
credentials or data that may already have been exposed.

## Validate without executing payloads

Use inert fixtures and both positive and negative matching cases. A harmless
lockfile can exercise a package rule; plain text can exercise an artifact rule.
Never install the malicious package or execute its payload to test a signature.

For an incident fixture under `testdata/incidents/example`, run from the repo root:

```sh
go test ./internal/incidents ./internal/detectors/incident
chdora scan testdata/incidents/example --incidents ./incidents --offline --skip-heuristic --skip-predictive
```

The fixture path is illustrative; create it for your entry. Verify the exact
incident ID, package/version, severity and source path in the result. Add a benign
control that must not match, especially for generic filenames and wildcard rules.

A pull request should include the source references, matching rationale, fixtures
and test results. Ordinary dependency CVEs belong in the relevant advisory source;
use the incident pack for additional confirmed incident evidence.

## Distribution

Release archives contain an incident snapshot. `chdora update` fetches the pack
from `main` into `~/.chaindora/incidents` and reports added, updated, unchanged
and skipped files. Updates are independent of the executable. For an explicitly
selected snapshot, use `--incidents /path/to/incidents` when scanning.

Implementation references: [matcher](../internal/detectors/incident/incident.go),
[fix-plan generation](../internal/detectors/incident/fix.go), and
[update command](../internal/cli/update.go).
