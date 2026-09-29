import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
@Component({
  selector: 'cd-footer', standalone: true, imports: [RouterLink],
  template: `
    <footer class="container">
      <div class="footer-top"><div><a class="footer-brand" routerLink="/">chaindora<span>.</span></a><p>Supply-chain security.<br>Five ecosystems. Sharper focus.</p></div><nav aria-label="Project links"><a href="https://github.com/alessandro-bitetto/chaindora">Source ↗</a><a href="https://github.com/alessandro-bitetto/chaindora/releases">Releases ↗</a><a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/threat-model.md">Threat model ↗</a><a href="https://github.com/alessandro-bitetto/chaindora/blob/main/SECURITY.md">Security disclosure ↗</a></nav></div>
      <div class="footer-bottom"><span>© Chaindora contributors · Apache-2.0</span><span>No telemetry. Not affiliated with any registry.</span></div>
    </footer>`,
  styles: [`
    footer { padding-top: 45px; padding-bottom: 26px; }.footer-top { display: flex; justify-content: space-between; gap: 35px; padding-bottom: 38px; }.footer-brand { font: 26px var(--cd-display); letter-spacing: -.06em; }.footer-brand span { color: var(--cd-red); }.footer-top p { font-size: 11px; color: var(--cd-muted); margin-top: 12px; line-height: 1.8; }nav { display: grid; grid-template-columns: 1fr 1fr; gap: 15px 44px; align-content: center; font-size: 11px; }nav a:hover { color: var(--cd-red); }.footer-bottom { display: flex; justify-content: space-between; gap: 20px; border-top: 1px solid var(--cd-line); padding-top: 21px; font: 9px/1.7 var(--cd-mono); color: var(--cd-muted); }
    @media(max-width: 600px) { .footer-top, .footer-bottom { flex-direction: column; }nav { gap: 15px 25px; }.footer-bottom { gap: 8px; } }
  `],
})
export class FooterComponent {}
