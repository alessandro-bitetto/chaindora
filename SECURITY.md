# Security policy

## Reporting a vulnerability in `chaindora` itself

If you've found a vulnerability in `chaindora` (the scanner — not in
something it detects), please **do not** open a public GitHub issue.

Use GitHub's private vulnerability reporting flow on this repository:

  https://github.com/alessandro-bitetto/chaindora/security/advisories/new

Include:
- A description of the issue and its impact.
- A minimal reproducer (commit SHA, command line, sample input).
- Your assessment of severity.
- Whether you'd like credit in the advisory.

We aim to acknowledge reports within 72 hours and to publish a fix or
mitigation within 30 days, depending on severity. You'll be kept in the
loop throughout.

## Supported versions

Until `chaindora` reaches `v1.0.0` only the most recent minor release
receives security fixes. After `v1.0.0` we'll commit to a longer support
window.

| Version | Supported |
|---|---|
| `0.16.x` | yes |
| `< 0.16` | no |

## Out of scope

The following are **not** vulnerabilities in `chaindora`:

- **A real supply chain attack that `chaindora` failed to detect.**
  That's coverage we'd love to add — please open a normal issue or, even
  better, an incident-pack PR (see
  [docs/incident-pack.md](./docs/incident-pack.md)).
- **A finding that turns out to be a false positive.** Open a regular
  issue with the input that triggered it; we'll tighten the detector.
- **A vulnerability in a dependency `chaindora` reports on.** Report it
  to that project upstream.

## Disclosure policy

We follow coordinated disclosure. Once a fix is shipped we publish a
GitHub Security Advisory with credit to the reporter (if requested) and
a write-up sufficient for downstream users to assess their exposure.
