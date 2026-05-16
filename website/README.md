# chaindora.dev website

Angular 18 application that builds the static landing page at
[chaindora.dev](https://chaindora.dev).

Single-page app, standalone components, dark theme, brand red
`#da2f2f` from the logo. Builds to a static bundle that drops onto
any host (GitHub Pages, Cloudflare Pages, Netlify, Vercel, S3).

## Develop

```sh
cd website
npm install
npm start             # serves at http://localhost:4200, hot reload
```

## Build for production

```sh
npm run build
# Output is in website/dist/
```

The `dist/` directory is ready to upload as-is to any static host.
Configure your host to serve `index.html` for unmatched routes (SPA
fallback) — every host has a one-line setting for this:

| Host | Setting |
|---|---|
| Cloudflare Pages | "Single page application" toggle in build config |
| Netlify | `[[redirects]] from = "/*" to = "/index.html" status = 200` in `netlify.toml` |
| Vercel | `{ "rewrites": [{ "source": "/(.*)", "destination": "/" }] }` in `vercel.json` |
| GitHub Pages | Add a `404.html` that's a copy of `index.html` |
| Nginx | `try_files $uri /index.html;` in the location block |

## Layout

```
website/
├── angular.json             Angular build config
├── package.json             Deps + scripts
├── tsconfig.json            TypeScript config
├── tsconfig.app.json
└── src/
    ├── index.html           HTML shell with <cd-root>
    ├── main.ts              bootstrapApplication entry
    ├── styles.scss          global styles + CSS variables for the brand
    ├── favicon.ico
    ├── assets/              logo / favicon (copied from ../../logo)
    └── app/
        ├── app.component.ts          shell with header + footer
        ├── app.config.ts             root config (router)
        ├── app.routes.ts             routes
        ├── components/
        │   ├── header.component.ts   sticky site header
        │   └── footer.component.ts   site footer with link columns
        └── pages/
            └── home/                 single landing page
                ├── home.component.ts
                ├── home.component.html
                └── home.component.scss
```

## Editing content

The home page sources its data (attack-class matrix, ecosystem list,
roadmap) from typed properties on `HomeComponent` — see
`src/app/pages/home/home.component.ts`. Update those arrays to reflect
new releases or new features; the table layout and styling stay the
same.

## Brand

Per [the official brand guide](../../logo/PDF%20Guideline.pdf) — the
palette is three colors, the display font is Permanent Marker, and the
logo is the bundled ninja + wordmark asset. Don't add new colors or
new fonts.

| Token | Value | Notes |
|---|---|---|
| Black | `#000000` | Text, primary borders, dark CTA backgrounds |
| Brand red | `#DA2F2F` | Accent, primary button, hover states |
| White | `#FFFFFF` | Background, light surfaces |
| Display font | Permanent Marker 400 | Logo wordmark, hero H1, "closing" headline only |
| Body font | system sans-serif (`-apple-system`, `Segoe UI`, `Inter`, …) | Long-form reading |
| Mono font | `"SF Mono", "JetBrains Mono", "Fira Code", Consolas, monospace` | Code blocks, command names |

Logo asset: `src/assets/logo.svg` (transparent-background SVG of the
official mark). Symbol-only: `src/assets/logo-symbol.png`. Favicon:
`src/favicon.ico` (also at `src/assets/favicon.ico`). All sourced from
the brand kit at `../../logo/`.

Design tokens live in `src/styles.scss` as CSS custom properties under
`:root`. Permanent Marker is loaded from Google Fonts in the same
file.

## Deploy

The site is intentionally simple to deploy:

```sh
npm run build
# Upload website/dist/ to your static host
```

For GitHub Pages with a custom domain on `chaindora.dev`:

```sh
npm run build
echo "chaindora.dev" > dist/CNAME
# Push dist/ to the gh-pages branch
```

For automated deploys, point your hosting platform at this repo,
build command `cd website && npm install && npm run build`, output
directory `website/dist`.
