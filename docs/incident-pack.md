# Contributing to the incident pack

The **incident pack** is the curated list of YAML files under
[`incidents/`](../incidents/) describing real supply-chain attacks. It's
the single most valuable thing in this repository — every entry catches
attacks that OSV.dev hasn't (or can't) catalog, and it's the only thing
that scales by community contribution rather than developer time.

This document is the contributor walkthrough. The formal schema reference
lives at [incidents/SCHEMA.md](../incidents/SCHEMA.md).

## What's an incident-pack entry?

A YAML file describing one supply-chain incident, with three kinds of
detection hooks:

1. **`packages`** — specific `(ecosystem, name, version)` tuples that
   were compromised. Match in any project's inventory triggers a
   `[CRITICAL] [incident-pack]` finding.
2. **`file_artifacts`** — filesystem globs whose presence anywhere in
   a scan tree (or the `$HOME` directory under `chdora forensics`)
   indicates compromise. Optional `content_substr` gating prevents false
   positives on generic filenames.
3. **`references`** — authoritative sources, displayed alongside every
   finding so reviewers have somewhere to click.

The shipped entries cover Shai-Hulud (Sep 2025), the qix chalk/debug
compromise (Sep 2025), the ctx PyPI takeover (May 2022), and
ua-parser-js (Oct 2021). They're all under 50 lines each — incidents
benefit from focus, not exhaustive detail.

## When to add an entry

Good candidates:

- A maintainer-account compromise of an established package.
- A typosquat / dependency-confusion campaign targeting a specific
  organization.
- A worm with a deterministic filesystem signature (the Shai-Hulud
  `shai-hulud-workflow.yml` file is the prototype case).
- An IDE / build-tool plugin compromise (Cursor, JetBrains, VS Code
  extensions).
- A registry-side attack (npm, PyPI, RubyGems, crates.io takedowns).

Less suitable:

- Generic vulnerabilities already in OSV.dev. The OSV-IOC detector
  catches those automatically; no curation needed.
- Reports without at least one authoritative source. We err on the side
  of *not* shipping false positives, which means we need a citation.

## Sourcing data

Reliable sources, ranked roughly by signal:

1. **The compromised project's own security advisory** (`SECURITY.md`,
   GitHub Security Advisory, project blog).
2. **First-party vendor research**: Socket, Aikido, StepSecurity, Phylum,
   Snyk, JFrog, Wiz, Datadog. Each publishes detailed write-ups for
   incidents they investigate.
3. **CISA / national CERT alerts** when applicable.
4. **NVD / GitHub Advisory Database** for CVE-tracked items.

For version pinning specifically, the authoritative source is the
registry's own yank/deprecation record. `npm view <pkg> versions` and
`pip index versions <pkg>` show what's currently published; missing
versions vs. an attacker write-up tell you what got yanked.

When you only have package names but no exact versions, **list the
package names and leave the `versions:` array empty**, with a YAML
comment pointing to the source. Under-matching is better than
false-positive amplification.

## Adding a new entry: step by step

1. **Pick an ID.** Format: `<ECOSYSTEM>-<NAME>-<DATE>` in uppercase
   kebab-case. Example: `NPM-LEFTPAD-2024-08`. Keep it short and
   googleable.

2. **Pick a filename.** Lowercase the ID and add `.yaml`. Example:
   `incidents/npm-leftpad-2024-08.yaml`. (Filename matching the ID makes
   PR diffs easier to grep.)

3. **Write the descriptor.**

   ```yaml
   schema: 1
   id: NPM-LEFTPAD-2024-08
   name: leftpad supply-chain compromise
   severity: critical
   date: "2024-08-19"
   summary: |
     One-paragraph plain-English description. What was compromised, what
     the attacker did, what's at stake for someone who installed an
     affected version.
   references:
     - "https://socket.dev/blog/leftpad-incident"
     - "https://example.com/cisa-alert"

   packages:
     - ecosystem: npm
       name: "left-pad"
       versions:
         - "1.4.1"
         - "1.4.2"
       safe_version: "1.4.3"   # optional; drives upgrade-command fixes

   file_artifacts:
     - glob: "**/.lefthood-data.json"
       severity: high
       description: Attacker-deployed exfiltration blob.
       content_substr: "trufflehog"

   post_compromise:            # optional; surfaced as ManualSteps at fix time
     - "Rotate any npm tokens published from machines that installed 1.4.1 / 1.4.2."
   ```

   Use `versions: ["*"]` only for pure-malware namespaces (typosquats,
   dependency-confusion packages where the entire name is
   attacker-controlled — never for legitimate packages where only a
   subset of versions are compromised).

4. **Run the tests.** From the repo root:

   ```sh
   go test ./internal/incidents/         # YAML loader
   go test ./internal/detectors/incident/ # matcher
   ```

   If you added a fixture demonstrating the match, also run:

   ```sh
   go build -o chdora ./cmd/chdora
   ./chdora scan testdata/<your-fixture> --skip-osv
   ```

5. **Open a PR.** One incident per PR. In the description:
   - Link the source(s) you used.
   - Note any uncertainty (versions you couldn't verify, packages you
     suspect but didn't include).
   - Note whether the affected versions have been yanked from the
     upstream registry.

## Quality bar

A reviewer will check:

- **ID format** matches the convention.
- **At least one authoritative reference** is present.
- **Severity** is appropriate (CRITICAL for active RCE / credential
  stealer; HIGH for confirmed-malicious but lower-impact; MEDIUM
  rarely — most incident-pack entries are CRITICAL or HIGH).
- **`file_artifacts`** gates with `content_substr` for filenames that
  have legitimate uses elsewhere (e.g. `data.json`).
- **No regex injection** via untrusted strings in `content_substr`
  (the matcher uses substring matching, not regex, but be aware).
- **Versions** are conservatively pinned to confirmed-malicious
  releases — not a broad range "just in case".

## Updating an existing entry

Same flow, but:

- Bump `date:` to the latest material change.
- Don't change the `id:` — downstream users may have already
  acknowledged that ID in their issue trackers.
- Document the diff (what's new, what was wrong) in the PR description.

## Keeping your local copy fresh

Each `chdora` binary ships with whatever was in `incidents/` at build time.
To pick up entries added upstream after that, run:

```sh
chdora update
```

This fetches the latest `incidents/*.yaml` files via the GitHub Contents
API and writes them atomically into `~/.chaindora/incidents/`. `chaindora
scan` and `chdora ci` check that directory first, so the refresh takes
effect on the next run without rebuilding.

Recommended cadence:

- **Daily**: schedule `chdora update` in a cron / launchd / Task Scheduler
  job. Five seconds, ~10 KB.
- **Manually** after every notable supply-chain incident (Socket / Aikido /
  StepSecurity blog post). Don't wait for the next scheduled run.
- **In CI**: run `chdora update` *before* `chdora ci .` if the runner
  has network access. For air-gapped runners, bake the latest `incidents/`
  into the runner image at build time.

### Forks and private packs

If your organization maintains a private incident pack on top of the
upstream one, point `--source` at the same Contents API shape on your fork
or internal mirror:

```sh
chdora update --source https://api.github.com/repos/myorg/chaindora-incidents/contents?ref=main
```

The endpoint just needs to return the same JSON shape (an array of objects
with `name`, `type`, and `download_url` fields).

## Governance

The incident pack is maintained in-tree. Anyone can open a PR; merges
require review by at least one maintainer. As the pack grows we may
introduce additional reviewers per ecosystem (a "JavaScript area
maintainer", etc.) — for now the bar is "the maintainer has reviewed
the sources and they check out".

If you want to track an incident that touches a private organization
(e.g. a confidential vendor write-up you can't link publicly), open an
issue rather than a PR — we'll work out how to land the entry without
losing the citation trail.
