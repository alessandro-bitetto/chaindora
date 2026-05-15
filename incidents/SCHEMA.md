# Incident pack schema (v1)

Each `incidents/*.yaml` file describes one supply-chain incident. The detector
matches the inventory of installed packages and the scanned filesystem against
these descriptors and emits findings tagged `detector: incident-pack`.

Contributions welcome — see [SHA references in each file](.) for source-of-truth
links per incident.

## Fields

```yaml
schema: 1                       # required, version of this schema
id: NPM-FOO-2026                # required, unique identifier (uppercase-kebab)
name: "Human-readable name"     # required
severity: critical              # critical | high | medium | low
date: "2026-01-15"              # ISO-8601 date the incident was disclosed
summary: |                      # multi-line description
  What happened, what the malware does, blast radius.
references:                     # at least one URL to an authoritative source
  - "https://example.com/blog/incident"

# Package version matches. Every entry generates one finding per matched
# (inventory package, version) pair.
packages:
  - ecosystem: npm              # npm | PyPI | GitHub Actions
    name: "@scope/pkg"
    versions:
      - "1.2.3"
      - "1.2.4"

# Filesystem artifacts. The scanner walks the scan root, computes each file's
# path relative to the root (with /-separators), and checks every glob.
#
# Supported glob syntax:
#   **/foo/bar    matches any file whose relative path ends with foo/bar
#   foo/bar       exact filepath.Match (no recursive ** support)
#
# `content_substr` (optional) gates the match: the artifact is only flagged
# if the file's contents contain that substring. Useful for noisy filenames
# (e.g. data.json) where the filename alone is too generic.
file_artifacts:
  - glob: "**/.github/workflows/shai-hulud-workflow.yml"
    severity: critical
    description: |
      One-line explanation of why this artifact indicates compromise.
  - glob: "**/data.json"
    severity: high
    description: Possible exfiltrated credential blob.
    content_substr: "trufflehog"
```

## Authoring guidance

- **Be precise about versions.** Listing entire version ranges without
  justification produces false positives at scale. Cite the upstream advisory.
- **Annotate uncertainty.** If you only have package names but not exact
  versions, list the package with a YAML comment pointing to the source —
  better to under-match than to over-match.
- **One incident per file.** Keep files focused so reviewers can diff them
  cleanly.
- **Filenames should match `id`** (lowercase, with `.yaml` extension).
