# chaindora.dev

Angular 18 static landing page. The design keeps the black/white/red brand,
Permanent Marker display face and bundled ninja mascot, with a clear
prevention/detection story and a five-ecosystem support explorer.

## Develop and build

```sh
npm ci
npm start
npm run build
```

Run from `website/`. Development serves on port 4200; production files are in
**`dist/browser/`**. Serve that directory with a static host. No deployment is
performed by a local build.

## Content and interactions

- `src/app/pages/home/home.component.ts`: five ecosystem records, command
  examples, selection and clipboard state. Examples show syntax, not safety.
- `home.component.html` / `.scss`: hero, prevention/detection switch, keyboard
  ecosystem tabs, protection boundaries and installation steps.
- `src/app/components`: responsive navigation and footer.
- `src/styles.scss`: typography, focus styles, reduced motion and brand tokens.
- `src/index.html`: metadata and social descriptions.

Verify desktop and narrow layouts, navigation anchors, mobile menu, both CLI
modes, all ecosystem tabs (including arrow/Home/End keys), copy feedback and
focus visibility. Keep README and product claims aligned: a supported package
manager is not a guarantee that every command is gated. Terminal output in the
hero is explicitly illustrative.

Brand colors: black `#000000`, red `#DA2F2F`, white `#FFFFFF`; neutral gray for
secondary text and rules. Permanent Marker is loaded from Google Fonts. Body
and monospace text use system font stacks. The original mascot is
`src/assets/logo-symbol.png`; use existing assets rather than inventing a new mark.
