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
| `website/package.json` | npm project `chaindora-website`; scripts `start` (`ng serve`), `build` (`ng build`), `watch`, `test`; Angular 18.2, TypeScript 5.5; `overrides` pin chokidar/readdirp/esbuild |
| `website/angular.json` | Single project `chaindora-website`, `@angular-devkit/build-angular:application` builder, `outputPath: dist`, prefix `cd`, SCSS, production budgets (500kb warn / 1mb error initial) |
| `website/wrangler.toml` | Cloudflare deploy: assets served from `./dist/browser`, `not_found_handling = "single-page-application"` |
| `website/tsconfig.json`, `website/tsconfig.app.json` | TypeScript config; app entry `src/main.ts` |
| `website/README.md` | Dev/build instructions and per-host SPA-fallback table |
| `website/src/index.html` | HTML shell with `<cd-root>`, `<base href="/">`, OG/Twitter meta, favicons from `assets/` |
| `website/src/main.ts` | `bootstrapApplication(AppComponent, appConfig)` |
| `website/src/styles.scss` | Global styles and brand CSS variables (brand red `#da2f2f`) |
| `website/src/app/app.config.ts` | Providers: zone change detection with event coalescing, `provideHttpClient`, router with in-memory scrolling and anchor scrolling |
| `website/src/app/app.routes.ts` | Routes: `''` → `HomeComponent` (title `chaindora`), `**` → redirect to `''` |
| `website/src/app/app.component.ts` | `cd-root` shell: `<cd-header>`, `<main><router-outlet>`, `<cd-footer>` in a flex column |
| `website/src/app/components/header.component.ts` | Sticky header: brand link, anchor links `#prevention` / `#detection` / `#install`, external Threat model and GitHub links |
| `website/src/app/components/footer.component.ts` | Footer link columns: page anchors (incl. `#fleet`), docs on GitHub, releases, changelog, issues, SECURITY.md |
| `website/src/app/pages/home/home.component.ts` | `cd-home`: fallback `version`, install snippets (`unixInstall`, `windowsInstall`), clipboard `copy()`, GitHub latest-release fetch in `ngOnInit`, `roadmap` phases (now / next / later) |
| `website/src/app/pages/home/home.component.html` | Landing sections: hero, modes (prevention/detection cards), catches, install, coverage grid, fleet, roadmap, closing |
| `website/src/app/pages/home/home.component.scss` | Home page styles |
| `website/src/assets/` | Logo (`logo.svg`, `logo.png`, `logo-symbol.png`) and favicon PNG sizes |

## Surface

**Exposes** — a static browser bundle in `website/dist/browser/` (`index.html`, hashed JS/CSS, `assets/`). One client-side route `/`; every other path redirects to `/` and must be served by the host's SPA fallback. Dev server via `ng serve` on port 4200 (Angular default; the `start` script sets no host, so it binds localhost by default). No backend API, no server-side code.

**Consumes** — no environment variables and no build-time configuration. Runtime browser calls: `GET https://api.github.com/repos/alessandro-bitetto/chaindora/releases/latest` (to display the current version; falls back to the hard-coded `version` field on error). All links target `github.com/alessandro-bitetto/chaindora`. npm packages: `@angular/*` 18.2, `rxjs` 7.8, `zone.js` 0.14, `tslib`; devDependencies `@angular/cli`, `@angular-devkit/build-angular`, `@angular/compiler-cli`, `typescript`. Build needs Node.js and `npm ci` from `website/package-lock.json`.

## Behavior

- **Bootstrap**: `main.ts` boots `AppComponent` with `appConfig`; the router renders `HomeComponent` at `/`. Anchor links (`#prevention`, `#detection`, `#install`, `#fleet`) scroll within the single page thanks to `anchorScrolling: 'enabled'`.
- **Version display**: `HomeComponent.ngOnInit` fetches the latest GitHub release tag over `HttpClient`, strips the leading `v`, and replaces the fallback `version` (`0.16.0` at time of writing). Network failure or rate limiting silently keeps the fallback.
- **Install snippets**: kept as TypeScript string constants in the component, not in the template, because their shell `${…}` / `%{…}` braces would be parsed by Angular's control-flow template compiler. Both resolve the latest release at run time rather than pinning a version. `copy()` writes to the clipboard and flashes "Copied" on the button for 1.5s.
- **Roadmap**: a static `roadmap` array of three phases (`now`, `next`, `later`) rendered by the template; edit the array, not the HTML, to change roadmap content.
- **Build**: `npm run build` → production configuration by default (`outputHashing: all`, budgets enforced), output in `website/dist/browser/`. `wrangler.toml` points Cloudflare at that directory with SPA not-found handling.
- **Serve**: any static host works; the host must rewrite unmatched paths to `index.html` (see the table in `website/README.md`).

## Notes

- The website is **excluded from the repo's dogfood CI scan** (`chdora ci . --exclude website`) because Angular CLI build tooling carries its own CVE surface that does not ship with the `chdora` binary. Do not remove that exclusion without expecting new findings.
- `package.json` lists `webpack`, `webpack-dev-server`, `ajv`, `picomatch`, `tmp` as runtime `dependencies` even though they are build-time; they exist to pin patched versions for the audit surface. `overrides` pins `esbuild` to exactly `0.23.0`.
- Component selector prefix is `cd` (`cd-root`, `cd-header`, `cd-footer`, `cd-home`). All components are standalone; there is no NgModule.
- The fallback `version` string in `home.component.ts` and the `version` in `package.json` drift from the actual latest tag (CHANGELOG shows 0.16.2). Only the runtime GitHub fetch is authoritative on the live page.
- `index.html` declares `<base href="/">`; deploying under a sub-path requires `ng build --base-href`.
- The build output directory is `dist/browser` (Angular application builder layout), not `dist/` directly; `wrangler.toml` already accounts for this but hand-written host configs must too.
- No Dockerfile, no `.infrar/build.yaml`, and no server component exist for this node; a containerised deployment would need a static file server (e.g. nginx with `try_files $uri /index.html`) added on top of the build output.
