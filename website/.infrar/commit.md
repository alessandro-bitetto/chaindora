---
schema_version: 1
id: 731edad3-c949-4cc3-99a3-c249fd23e968
name: website
node: website
branch: feature/website-version-from-release-tag
previous_commit: bd99d7716856fa0266cfab671b347cfce26d1f0b
---

## What changed

- `website/src/app/pages/home/home.component.ts`: the fallback `version` is no longer a hand-edited literal (`'0.16.0'`); it is initialised from `import { version as packageVersion } from '../../../../package.json'`. The runtime GitHub releases fetch still overrides it.
- `website/tsconfig.json`: added `"resolveJsonModule": true` so TypeScript accepts the JSON import (the Angular esbuild builder already handled JSON; esbuild tree-shakes everything but `version` out of the bundle).
- `website/package.json` and `website/package-lock.json`: version stamped to `0.16.2`, the latest tag, via the new script (they read 0.16.1 before).
- `website/README.md`: new "Version display" section describing where the version comes from and how it is bumped.
- Verified with `npm ci && npm run build`: production build succeeds and `dist/browser/main-*.js` contains `0.16.2` and none of the other package.json fields.

## Why

The hero and download button showed a fallback version that had to be edited by hand in two places and had drifted three releases behind (0.16.0 in the component, 0.16.1 in package.json, 0.16.2 tagged). Making `package.json` the single source and importing it at build time leaves exactly one field to bump, and that bump is now done by the release flow (`scripts/website-version.sh set`) and enforced by the release workflow, so the number can no longer drift silently.
