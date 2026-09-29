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
  - ecosystem: npm              # npm | PyPI | GitHub Actions | Homebrew | Debian
                                # | Browser Extension | IDE Extension | Go
    name: "@scope/pkg"
    versions:
      - "1.2.3"
      - "1.2.4"
      # The literal "*" matches any version. Use for typosquats and
      # other packages where the *entire namespace* is malware (e.g.
      # python3-dateutil, jeIlyfish, torchtriton on public PyPI).
    safe_version: "1.2.5"       # optional; when set, the fix layer
                                # emits an upgrade command (`npm
                                # install pkg@1.2.5`, `pip install
                                # --upgrade pkg==1.2.5`, etc) instead
                                # of a bare uninstall.

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

# Optional list of additional manual steps that the fix layer should
# surface when any match for this incident fires (package or artifact).
# Use this for incident-specific credential-rotation guidance that the
# generic "audit credentials" catch-all wouldn't cover. The fix runner
# never auto-applies these — they are always presented as ManualSteps
# for the user to follow.
post_compromise:
  - "Rotate the npm token in ~/.npmrc on any machine that ran `npm install` during the attack window."
  - "Revoke and re-issue npm 2FA recovery codes on affected accounts."
```

## Authoring guidance

- **Be precise about versions.** Listing entire version ranges without
  justification produces false positives at scale. Cite the upstream advisory.
- **Annotate uncertainty.** If you only have package names but not exact
  versions, list the package with a YAML comment pointing to the source —
  better to under-match than to over-match.
- **Use `"*"` only for pure-malware namespaces.** Typosquats, dependency-
  confusion packages, and other cases where the *whole package name* is
  attacker-controlled are appropriate. Don't use `"*"` for legitimate
  packages where only some versions were compromised — list those versions
  explicitly.
- **`safe_version` is one string, not a range.** Pick the version you'd
  recommend the user pin to: usually the post-incident clean release, or
  the last clean release before the malicious one for sabotage incidents.
- **One incident per file.** Keep files focused so reviewers can diff them
  cleanly.
- **Filenames should match `id`** (lowercase, with `.yaml` extension).
- **`post_compromise` is for incident-specific guidance only** — the fix
  layer already appends generic "audit credentials / verify dep tree"
  steps to every plan. Use this field for the steps a *defender* of this
  specific incident would do (e.g. "rotate the npm token from ~/.npmrc",
  "check for outbound connections to xmr.f2pool.com").
