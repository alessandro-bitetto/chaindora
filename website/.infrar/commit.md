---
schema_version: 1
id: 731edad3-c949-4cc3-99a3-c249fd23e968
name: website
node: website
branch: feature/website-ui-polish
previous_commit: bd99d7716856fa0266cfab671b347cfce26d1f0b
---

## What changed

- `src/styles.scss`: introduced design tokens (fluid type scale via `clamp()`, `--cd-section-y` section rhythm, shadows, gutter), a shared `.section` / `.section-shaded` / `.section-head` / `.section-eyebrow` / `.section-lede` stack, `scroll-padding-top` so anchor links land below the sticky header, `:focus-visible` rings, `prefers-reduced-motion` handling, taller buttons with a primary shadow, and a mobile `pre` override that keeps the terminal-chrome top padding. Moved the Permanent Marker font from a CSS `@import` to a `<link>` in `index.html` with preconnects.
- `components/header.component.ts`: scroll-aware border/shadow, hover underline on nav links, and a hamburger mobile panel (`menuOpen`) listing Prevention / Detection / Install / Fleet mode / Threat model / GitHub; closes on link click, Escape or resize past 720px.
- `components/footer.component.ts`: mono uppercase column headings, muted links with hover shift, centred red rule on the top border, responsive 4 → 3 → 2 column grid.
- `pages/home/home.component.html`: every section wears `section` and opens with a `.section-head` (eyebrow → display h2 → lede); hero facts became wrapping chips with the version linked to the latest release; coverage stat tiles gained a `.cstat-text` wrapper; install OS labels became tab-style captions; version now renders as `v{{ version }}`. Copy, anchors (`#prevention`, `#detection`, `#install`, `#fleet`) and all links unchanged.
- `pages/home/home.component.scss`: rewritten around the shared tokens — hero dot-grid texture and fluid sizes, hover elevation on mode cards, red rail on the detection catches column, a vertical rail joining the install steps (numbers stay left on phones), copy button restyled for the dark title bar, coverage stats as horizontal tiles, ecosystem pills in a 4/3/2/1 column grid with name-over-tools layout, fleet band and roadmap phases (active phase emphasised, stacking at ≤900px), closing card glow, and consolidated breakpoints at 1000 / 900 / 720 / 560 / 380px. Removed ~90 lines of dead coverage-tier CSS.
- `pages/home/home.component.ts`: fallback `version` bumped from 0.16.0 to 0.16.2 to match the current tag.

## Why

The landing page had inconsistent vertical rhythm (per-section margins mixed with a global `h2` margin), heading sizes that jumped at a single breakpoint, no mobile navigation beyond the GitHub button, anchor targets hidden under the sticky header, and a coverage grid whose inline name/tools layout wrapped raggedly. The refresh gives every section the same head stack and spacing scale, makes typography fluid, adds keyboard focus and reduced-motion support, and verifies (via a production build and Playwright at 320–1440px) that no width overflows the viewport, while keeping the brand red / black / white palette and all existing content and links intact.
