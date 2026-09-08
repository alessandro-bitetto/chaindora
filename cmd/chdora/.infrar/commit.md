---
schema_version: 1
id: 9a4d554a-d80e-4fbd-bba0-2bbace118466
name: chdora
node: cmd/chdora
branch: feature/website-version-from-release-tag
previous_commit: bd99d7716856fa0266cfab671b347cfce26d1f0b
---

## What changed

- New `scripts/website-version.sh` (POSIX sh, needs node + npm): `set vX.Y.Z` runs `npm version --no-git-tag-version --allow-same-version` in `website/` so `package.json` and `package-lock.json` follow the tag; `check vX.Y.Z` exits 1 with a diagnostic when either disagrees. Rejects inputs that are not a semver triple.
- `.github/workflows/release.yml`: new step before goreleaser, `scripts/website-version.sh check "$GITHUB_REF_NAME"`, so a tag whose website version drifted fails the release instead of publishing.
- `CLAUDE.md`: release flow gains step 2 (stamp the website version) and describes the fail-closed check; repo layout lists `scripts/`.
- `docs/maintainer-handoff.md`: same release-flow update plus the recovery recipe when the check fails on an unpublished tag.
- `CHANGELOG.md`: `[Unreleased]` entry describing the change.
- No Go code changed; `chdora` itself still takes its version from goreleaser's ldflags.

## Why

The release flow is the only moment the "released version" is known for certain, so it is the right place to stamp the website's fallback version. Doing it with a script keeps the one-commit-per-tag convention (the stamp lands in the release commit), and the workflow check makes a forgotten stamp a loud failure at tag time rather than a stale number on chaindora.dev. The website build itself cannot derive the tag (Cloudflare clones without tags and builds before the release is published), which is why the value is committed rather than computed at build time.
