---
schema_version: 1
id: 731edad3-c949-4cc3-99a3-c249fd23e968
name: website
node: website
branch: feature/website-ui-polish
previous_commit: 57f02422c678da9dfb720e955073db37609002b5
---

## What changed

- `src/styles.scss`: added `--cd-accent-ink` (#c62828) for small red text on tinted surfaces and applied it to section eyebrows; raised `--cd-fg-subtle` and terminal comment alpha to pass 4.5:1; two-tone `:focus-visible` ring (red outline + white halo) with an `.on-dark` / `pre` / `.code-block` inversion; new `.skip-link`, `.visually-hidden` and `.skeleton` shimmer utilities; reduced-motion now also disables smooth scrolling and flattens the skeleton. Moved the horizontal overflow clip from `body` to `html` (with `overflow-x: clip` on body) — the body clip was turning body into the sticky header's scroll container.
- `src/app/app.component.ts`: "Skip to content" link as the first tabbable element and `<main id="main" tabindex="-1">` as its target.
- `src/app/app.config.ts`: `APP_INITIALIZER` that sets the router's `ViewportScroller` offset to the live header height + 16px, so `#install`-style anchors (nav, footer, deep links) land below the sticky header instead of underneath it.
- `src/app/components/header.component.ts`: sticky positioning moved to `:host`; sections rendered from one array on desktop and in a compact 2×2 mobile panel; in-view section tracking (scroll/resize/NavigationEnd, rAF-coalesced) marks the current link with `.active` + `aria-current="true"` (ties between side-by-side cards resolve to the URL hash); hamburger label flips Open/Close menu; panel also closes on outside click.
- `src/app/pages/home/home.component.ts`: `versionState` (loading / live / fallback) with a 6s timeout on the GitHub release lookup; `copy()` keyed by snippet with `copied` / `copyFailed` state, a clipboard fallback via `execCommand`, per-snippet names, and a live-region announcement.
- `src/app/pages/home/home.component.html`: hero version chip, install `code-status` tags and closing Download button render a skeleton while loading (`aria-busy`, visually-hidden text); copy buttons carry specific `aria-label`s ("Copy macOS / Linux install command", …) and template-bound Copied / Failed labels; a `role="status"` polite live region announces copy results; legend dots marked decorative; closing card tagged `on-dark`.
- `src/app/pages/home/home.component.scss`: copy button Copied (red, ✓) and Failed (✕) states, `.code-block.flash` red border/glow on the copied terminal, `.code-status` title-bar tag (hidden ≤560px), skeleton sizing for chip and button, hero version text in `--cd-accent-ink`, maturity badge text 9px → 10px.

## Why

The follow-up asked for accessibility basics, an in-view highlight in the mobile menu, a loading state for the version-dependent snippets and a clearer copy confirmation. Verifying those in a real browser also exposed two latent defects: the header was not actually sticking (body-level `overflow-x: hidden` plus an inline component host confined the sticky box), and anchor navigation parked every section heading under the header because Angular's anchor scrolling uses `window.scrollTo` and ignores `scroll-padding`. Both had to be fixed for the section highlighting to make sense. Brand red is kept for fills and display text; only small text on grey/pink backgrounds uses the slightly deeper `#c62828` so it clears AA. All content, anchors and links are unchanged. Verified with a production build (no warnings, within the component-style budget) and Playwright at 320–1440px: no horizontal overflow, header sticks, anchors land at header height + 16px, skip link → main → hero Install button, skeleton → live version, Copied state + live region text, mobile chip highlight follows the section in view.
