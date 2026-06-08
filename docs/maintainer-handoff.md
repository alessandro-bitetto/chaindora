# Maintainer handoff

Bus-factor doc for chaindora. Read this if you've inherited the project or
need to take over while the primary maintainer is unreachable. Pairs with
[CLAUDE.md](../CLAUDE.md) (architecture on-ramp) and
[docs/architecture.md](architecture.md) (internals).

This file deliberately enumerates **what would be lost if the primary
maintainer's laptop disappeared tonight**. If something below isn't backed
up off-laptop, fix that first.

---

## Critical: things only on the maintainer's machine

| Asset | Where | Recovery if lost |
|---|---|---|
| Goreleaser GPG signing key | local keyring | Regenerate, publish new pubkey, accept that pre-cutover releases stay verifiable against the old key |
| GitHub release-signing token | local `.env` or keychain | Rotate at <https://github.com/settings/tokens>; update repo secrets |
| `~/.chaindora/gate-cache/` | local disk | Rebuilt on first install per package; loss = lose republish-guard history on this machine only |
| `~/.chaindora/incidents/` (community pack) | local disk | Refetched by `chdora update` from upstream `incidents/` in the repo |
| `~/.chaindora/fix-plans/` | local disk | Per-user state; not shared, not recoverable, not critical |

**Action item if you're the new maintainer**: confirm GPG signing key is
exported to a secure offline store (paper backup or hardware token), and
that the GitHub token in repo secrets isn't tied to the old maintainer's
personal account.

---

## Release flow

The release is fully automated once a tag is pushed.

```sh
# 1. Update CHANGELOG.md: move [Unreleased] items to [X.Y.Z] — YYYY-MM-DD.
$EDITOR CHANGELOG.md

# 2. Commit + tag + push.
git commit -am "vX.Y.Z: <short subject>"
git tag -a vX.Y.Z -m "vX.Y.Z — <short subject>"
git push origin main && git push origin vX.Y.Z

# 3. .github/workflows/release.yml triggers on the tag and runs goreleaser.
#    Watch at: https://github.com/alessandro-bitetto/chaindora/actions
```

What goreleaser produces:

- Cross-platform archives (`chaindora_X.Y.Z_{linux,darwin,windows}_{amd64,arm64}.{tar.gz,zip}`)
- `chaindora_X.Y.Z_checksums.txt` — sha256 of every archive
- GPG-signed checksums file
- GitHub Release with the CHANGELOG section as the body

**Convention**: one commit per tag. `git log --oneline` is the design
history of this single-author OSS project. Don't squash, don't amend,
don't force-push tags.

---

## Infrastructure dependencies

| Service | Why we need it | Failure mode |
|---|---|---|
| GitHub (repo + releases + actions) | Source of truth, CI, release distribution | Hard dep. Mirror to GitLab/Codeberg as defensive measure. |
| `api.osv.dev` | Vulnerability data for `osv-malicious` and `osv-ioc` | Gate fails closed on outage (Verdict=Unknown → Block under Strict). Detection skips OSV layer with `--skip-osv`. |
| `registry.npmjs.org` and similar PM registries | `publisher-change`, `cooldown`, `maintainer-trust` checks | Per-ecosystem; same fail-closed semantics. |
| `sigstore.dev` (transparency log) | `provenance` checker for npm/PyPI Trusted Publishing | Warn-only on outage; doesn't block installs. |
| Homebrew tap (if/when shipped) | Distribution for `brew install chaindora` | Bus-factor: tap repo must have the same maintainer access. |

We do NOT depend on:

- Any paid SaaS (no Snyk, no Socket, no Datadog as a runtime dep)
- Any database server (server mode is single-file JSON)
- Any background daemon (chdora is one-shot per invocation)

---

## Repository permissions

The minimal set the maintainer needs:

- `alessandro-bitetto/chaindora` — admin (release tags, branch protection,
  Actions secrets)
- `pkg.go.dev` — listing auto-refreshes from public repo; no separate
  permissions needed
- `chaindora.dev` (when live) — DNS + hosting credentials; document where

If the maintainer is unreachable for >30 days, the recommended path is:

1. Fork to a new namespace (`chaindora/chaindora` org would be ideal)
2. Announce the fork on the existing repo's README (if you have write
   access) or as a GitHub issue
3. Re-cut releases under the new maintainer's signing key; document the
   key transition in CHANGELOG.

---

## "I just inherited this — what do I actually need to know?"

Read in this order:

1. [README.md](../README.md) — user-facing surface
2. [CLAUDE.md](../CLAUDE.md) — internal mental model + per-package
   gotchas. **The most important single doc.**
3. [docs/threat-model.md](threat-model.md) — what's in scope, what
   isn't, and the prioritization framework
4. [docs/architecture.md](architecture.md) — data flow
5. [docs/incident-pack.md](incident-pack.md) — the highest-leverage
   external contribution path
6. This file

Then run:

```sh
go build -o /tmp/chdora ./cmd/chdora
/tmp/chdora scan testdata --skip-osv
/tmp/chdora gate check lodash@4.17.21 --lenient --explain
go test ./... -race
```

If all four work, you have a working build. The first two exercise the
detection and prevention paths against the bundled fixtures.

---

## What you should NOT do

- Don't merge an incident-pack entry without an authoritative source URL
  in `references:`. See [docs/incident-pack.md](incident-pack.md).
- Don't add a new external Go dependency without a strong reason. Today:
  `cobra` + `yaml.v3`. Anything else needs justification.
- Don't change `findings.Finding` JSON field names without bumping
  `docs/schema/v1/finding.schema.json` — that schema is the wire
  contract for downstream consumers.
- Don't ship a release without running the full test matrix
  (`ubuntu-latest`, `macos-latest`, `windows-latest`).
- Don't force-push to `main`. Don't skip git hooks. Don't sign with a
  different key than the one in the Release artifacts.

---

## Contact for handoff questions

Issues: <https://github.com/alessandro-bitetto/chaindora/issues>
Security: see [SECURITY.md](../SECURITY.md)
