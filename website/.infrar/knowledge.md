---
schema_version: 2
id: 731edad3-c949-4cc3-99a3-c249fd23e968
name: website
node: website
category: app
---

## Purpose

Angular 18 static landing page for Chaindora 0.0.1. The five-ecosystem support
explorer and prevention/detection story are implemented in HomeComponent.

## Build and deploy

Run `npm ci` and `npm run build` in `website/`; serve `dist/browser`.
`wrangler.toml` configures Cloudflare static assets with an SPA fallback.
The generated build specification packages the same output with nginx.

## Navigation

Internal links use Angular RouterLink fragments. Router configuration enables
anchor scrolling and repeated same-URL navigation. ViewportScroller applies
the sticky header offset. External release/documentation links point to GitHub.
Source installation is pinned to `v0.0.1`.

See [website development](../README.md) for files, branding and browser checks.
