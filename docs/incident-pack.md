# Contributing to the incident pack

The incident pack is the curated set of YAML files under
[`incidents/`](../incidents/) describing known supply-chain attacks.
It's a small high-value resource — every entry catches attacks that
chaindora's other layers (OSV, heuristics, gate checks) can't or won't
flag on their own.

This document is the contributor walkthrough. The formal schema lives
at [incidents/SCHEMA.md](../incidents/SCHEMA.md).

## Relationship to OSV / MAL-*

chaindora's OSV-IOC detector federates the
[OpenSSF Malicious Packages feed](https://github.com/ossf/malicious-packages)
automatically. Every `MAL-*` entry in OSV.dev is already covered —
chaindora flags it as `[CRITICAL] [osv-ioc]` with
`Category=supply-chain-attack`. **You don't need to add an incident
YAML for a package that's already in OSV's malicious feed.**

The incident pack exists for the categories OSV doesn't index:

| What OSV covers | What the incident pack covers |
|---|---|
| Per-package CVEs (npm/PyPI/Maven/RubyGems/crates/Go) | OS-level supply-chain attacks (xz-utils, distro-level backdoors) |
| OpenSSF Malicious Packages (`MAL-*`) | Worms with file-artifact signatures (`shai-hulud-workflow.yml`) |
| Per-version-pinned vulnerability data | Maintainer sabotage / protest-ware (colors, faker) |
| | Browser / IDE extension takeovers (Great Suspender) |
| | Typosquat name lists where the malicious code is gone but the pattern is documented |

v0.7 trimmed the pack from 14 to 6 entries when chaindora gained OSV
federation. The current 6 entries are the ones that **wouldn't be caught
otherwise**.

## Current pack (6 entries)

```
incidents/
├── colors-faker-sabotage-2022.yaml    npm — author-sabotage protest-ware
├── great-suspender-2021.yaml          Chrome extension — takeover by new owner
├── pypi-typosquats-2019.yaml          PyPI — typosquat name list
├── qix-compromise-2025.yaml           npm — chalk/debug maintainer compromise
├── shai-hulud-2025.yaml               npm — worm with file-artifact signature
└── xz-utils-cve-2024-3094.yaml        OS — backdoor in build-time tool
```

## Entry anatomy

Every YAML carries three kinds of detection hooks:

1. **`packages`** — specific `(ecosystem, name, versions)` tuples.
   Inventory match fires `[CRITICAL] [incident-pack]`.
2. **`file_artifacts`** — filesystem globs. Optional `content_substr`
   gates against false positives on generic filenames. Used by
   `chdora forensics` and `chdora audit`'s file-artifact hunt.
3. **`references`** — authoritative source URLs. Displayed alongside
   every finding.

Optional:
- **`safe_version`** per package — the post-incident clean release.
  Drives the fix-plan layer to emit `npm install pkg@<safe>` /
  `pip install --upgrade pkg==<safe>` instead of a bare uninstall.
- **`post_compromise`** at top level — additional ManualSteps the fix
  runner surfaces when any match fires (credential rotation, log
  audit, etc.).

The wildcard `"*"` in `versions:` matches any version — use ONLY for
pure-malware namespaces (typosquats, dependency-confusion packages
named to impersonate a private scope).

## When to add an entry

Good candidates:

- **A maintainer-account compromise** of an established package where
  the malicious code has been yanked but the incident itself is worth
  preserving. The community knowledge — "this happened to ctx because
  X" — is the value.
- **A file-artifact signature** of a worm or post-compromise tool
  (`shai-hulud-workflow.yml`, `.aws/credentials.bak`, etc.).
- **A maintainer-sabotage event** (`colors` corrupting its own
  output, `faker` removing functionality). OSV doesn't catalog
  these because they're not CVEs in the traditional sense.
- **An OS-level supply-chain attack** like xz-utils — backdoor in a
  build-time tool that ended up in OpenSSH. Doesn't fit npm/PyPI/
  etc. OSV mappings.
- **A typosquat campaign** documented enough to enumerate the names.

Skip:

- Anything already covered by OSV's `MAL-*` feed (run
  `chdora update` to refresh first, then check).
- One-off CVEs in legitimate packages — those belong in OSV, not the
  incident pack.
- Speculative or unverified incidents — at least one authoritative
  source URL is required.

## Quality bar

A merge-ready entry must have:

- [ ] **At least one authoritative source URL.** Vendor advisory,
      research firm post-mortem, security blog by a recognized
      organization. Not Twitter alone.
- [ ] **Precise version ranges** (where applicable). `versions: ["*"]`
      is reserved for pure-malware namespaces.
- [ ] **A clear severity tier.** CRITICAL only for confirmed RCE /
      credential exfil / persistence. HIGH for sabotage. MEDIUM for
      typosquat patterns where the malicious version is gone.
- [ ] **`safe_version` where it applies.** The post-incident clean
      release. Drives the auto-fix path.
- [ ] **Conservative file_artifact globs.** Use `content_substr` to
      narrow matches on generic filenames.

## PR flow

1. Fork the repo, create a branch named `incident/<short-slug>`.
2. Copy [`incidents/SCHEMA.md`](../incidents/SCHEMA.md)'s template
   into a new YAML file in `incidents/`.
3. Fill in every required field. Add at least one reference URL.
4. Run `chdora scan testdata --incidents ./incidents --skip-osv` to
   exercise the matcher locally.
5. Add a `testdata/incidents/<slug>/` fixture if your entry has
   file-artifact globs — a single file matching each glob is enough.
6. Open the PR. Reviewers check: schema validity, source quality,
   severity calibration, false-positive risk.

Once merged, the entry ships with the next chdora release and is
fetched by `chdora update` from
[github.com/alessandro-bitetto/chaindora](https://github.com/alessandro-bitetto/chaindora)
into `~/.chaindora/incidents/` on any user machine that runs the
update command.

## Testing your entry

The incident-pack matcher has its own tests in
`internal/detectors/incident/`. A new entry deserves a fixture:

```yaml
# testdata/incidents/my-incident/package-lock.json
{
  "packages": {
    "": { "name": "test", "version": "1.0.0" },
    "node_modules/MALICIOUS_PKG": { "version": "1.2.3" }
  }
}
```

Then:

```sh
chdora scan testdata/incidents/my-incident --incidents ./incidents --skip-osv
```

You should see a `[CRITICAL] [incident-pack]` line referencing your
entry's ID.

## Pointers

- Schema reference: [incidents/SCHEMA.md](../incidents/SCHEMA.md)
- The matcher: `internal/detectors/incident/incident.go`
- Auto-fix integration: `internal/detectors/incident/fix.go`
- Update mechanism: `internal/cli/update.go` (fetches the pack from
  the upstream GitHub repo into `~/.chaindora/incidents/`)
