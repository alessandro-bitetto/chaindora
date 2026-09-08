---
schema_version: 2
id: 731edad3-c949-4cc3-99a3-c249fd23e968
name: website
node: website
category: app
---

## Purpose

`website/` is the chaindora.dev marketing landing page: a single-route Angular 18 standalone-component app that builds to a static bundle and is deployed independently of the `chdora` binary (Cloudflare via `wrangler.toml`, or any static host with SPA fallback).

## Files

| Path | Role |
|---|---|
| `website/package.json` | npm project `chaindora-website`; its `version` field is the **single in-repo source of the website's fallback version** (stamped from the release tag by `scripts/website-version.sh`); scripts `start` (`ng serve`), `build` (`ng build`), `watch`, `test`; Angular 18.2, TypeScript 5.5; `overrides` pin chokidar/readdirp/esbuild |
| `website/package-lock.json` | npm lockfile; its two top-level `version` fields are kept equal to `package.json` by the same script |
| `website/angular.json` | Single project `chaindora-website`, `@angular-devkit/build-angular:application` builder, `outputPath: dist`, prefix `cd`, SCSS, production budgets (500kb warn / 1mb error initial) |
| `website/wrangler.toml` | Cloudflare deploy: assets served from `./dist/browser`, `not_found_handling = "single-page-application"` |
| `website/tsconfig.json`, `website/tsconfig.app.json` | TypeScript config; `resolveJsonModule: true` so `package.json` can be imported; app entry `src/main.ts` |
| `website/README.md` | Dev/build instructions, the "Version display" section, and the per-host SPA-fallback table |
| `website/src/index.html` | HTML shell with `<cd-root>`, `<base href="/">`, OG/Twitter meta, favicons from `assets/` |
| `website/src/main.ts` | `bootstrapApplication(AppComponent, appConfig)` |
| `website/src/styles.scss` | Global styles and brand CSS variables (brand red `#da2f2f`) |
| `website/src/app/app.config.ts` | Providers: zone change detection with event coalescing, `provideHttpClient`, router with in-memory scrolling and anchor scrolling |
| `website/src/app/app.routes.ts` | Routes: `''` → `HomeComponent` (title `chaindora`), `**` → redirect to `''` |
| `website/src/app/app.component.ts` | `cd-root` shell: `<cd-header>`, `<main><router-outlet>`, `<cd-footer>` in a flex column |
| `website/src/app/components/header.component.ts` | Sticky header: brand link, anchor links `#prevention` / `#detection` / `#install`, external Threat model and GitHub links |
| `website/src/app/components/footer.component.ts` | Footer link columns: page anchors (incl. `#fleet`), docs on GitHub, releases, changelog, issues, SECURITY.md |
| `website/src/app/pages/home/home.component.ts` | `cd-home`: `version` initialised from the `package.json` import, install snippets (`unixInstall`, `windowsInstall`), clipboard `copy()`, GitHub latest-release fetch in `ngOnInit`, `roadmap` phases (now / next / later) |
| `website/src/app/pages/home/home.component.html` | Landing sections: hero, modes (prevention/detection cards), catches, install, coverage grid, fleet, roadmap, closing; renders `{{ version }}` in the hero and the download button |
| `website/src/app/pages/home/home.component.scss` | Home page styles |
| `website/src/assets/` | Logo (`logo.svg`, `logo.png`, `logo-symbol.png`) and favicon PNG sizes |
| `scripts/website-version.sh` (repo root) | `set vX.Y.Z` stamps `package.json` + lockfile via `npm version --no-git-tag-version`; `check vX.Y.Z` exits 1 if either disagrees with the tag. Called by the release flow and by `.github/workflows/release.yml` |

## Surface

**Exposes** — a static browser bundle in `website/dist/browser/` (`index.html`, hashed JS/CSS, `assets/`). One client-side route `/`; every other path redirects to `/` and must be served by the host's SPA fallback. Dev server via `ng serve` on port 4200 (Angular default; the `start` script sets no host, so it binds localhost by default). No backend API, no server-side code. Under Infrar the node builds with the Dockerfile inlined in `website/.infrar/build.yaml` (npm ci → `ng build` → nginx-unprivileged on 8080 with `try_files ... /index.html`).

**Consumes** — no environment variables. Build-time input: the `version` field of `website/package.json`, imported by `home.component.ts` (esbuild tree-shakes the rest of the file out of the bundle). Runtime browser calls: `GET https://api.github.com/repos/alessandro-bitetto/chaindora/releases/latest` (to display the current version; falls back to the build-time `version` on error). All links target `github.com/alessandro-bitetto/chaindora`. npm packages: `@angular/*` 18.2, `rxjs` 7.8, `zone.js` 0.14, `tslib`; devDependencies `@angular/cli`, `@angular-devkit/build-angular`, `@angular/compiler-cli`, `typescript`. Build needs Node.js and `npm ci` from `website/package-lock.json`.

## Behavior

- **Bootstrap**: `main.ts` boots `AppComponent` with `appConfig`; the router renders `HomeComponent` at `/`. Anchor links (`#prevention`, `#detection`, `#install`, `#fleet`) scroll within the single page thanks to `anchorScrolling: 'enabled'`.
- **Version display**: `HomeComponent.version` starts as the value imported from `package.json` (`import { version as packageVersion } from '../../../../package.json'`), i.e. the last released tag as stamped by the release flow. `ngOnInit` then fetches the latest GitHub release tag over `HttpClient`, strips the leading `v`, and replaces it. Network failure or rate limiting silently keeps the build-time value.
- **Version lifecycle**: release step 2 in the root `CLAUDE.md` runs `scripts/website-version.sh set vX.Y.Z`, which rewrites `package.json` and `package-lock.json` (no git side effects). On tag push, `release.yml` runs `scripts/website-version.sh check "$GITHUB_REF_NAME"` before goreleaser and fails the release on mismatch. Between releases the fallback legitimately lags the tag that is about to be cut.
- **Install snippets**: kept as TypeScript string constants in the component, not in the template, because their shell `${…}` / `%{…}` braces would be parsed by Angular's control-flow template compiler. Both resolve the latest release at run time rather than pinning a version. `copy()` writes to the clipboard and flashes "Copied" on the button for 1.5s.
- **Roadmap**: a static `roadmap` array of three phases (`now`, `next`, `later`) rendered by the template; edit the array, not the HTML, to change roadmap content.
- **Build**: `npm run build` → production configuration by default (`outputHashing: all`, budgets enforced), output in `website/dist/browser/`. `wrangler.toml` points Cloudflare at that directory with SPA not-found handling.
- **Serve**: any static host works; the host must rewrite unmatched paths to `index.html` (see the table in `website/README.md`).

## Notes

- **Never hand-edit a version literal** in `home.component.ts`; there is none any more. Bump `package.json` through `scripts/website-version.sh set` so the lockfile stays in step and the release check passes.
- `scripts/website-version.sh` needs `node` and `npm` on PATH (both modes); it accepts `vX.Y.Z` or `X.Y.Z` and rejects anything not shaped like a semver triple.
- The `package.json` import path is relative to `src/app/pages/home/`; moving the component means fixing the `../../../../` depth. The inline Dockerfile in `build.yaml` copies `package.json` into `/app` before `src/`, so the import resolves inside the container too.
- The website is **excluded from the repo's dogfood CI scan** (`chdora ci . --exclude website`) because Angular CLI build tooling carries its own CVE surface that does not ship with the `chdora` binary. Do not remove that exclusion without expecting new findings.
- `package.json` lists `webpack`, `webpack-dev-server`, `ajv`, `picomatch`, `tmp` as runtime `dependencies` even though they are build-time; they exist to pin patched versions for the audit surface. `overrides` pins `esbuild` to exactly `0.23.0`.
- Component selector prefix is `cd` (`cd-root`, `cd-header`, `cd-footer`, `cd-home`). All components are standalone; there is no NgModule.
- `index.html` declares `<base href="/">`; deploying under a sub-path requires `ng build --base-href`.
- The build output directory is `dist/browser` (Angular application builder layout), not `dist/` directly; `wrangler.toml` already accounts for this but hand-written host configs must too.
- There is no Dockerfile in `website/` itself; the container build lives only in `website/.infrar/build.yaml` and the pod manifest in `website/.infrar/iac-preview/website-pod.yaml` (nginx on 8080, TCP readiness).
