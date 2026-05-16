import { Component } from '@angular/core';

@Component({
  selector: 'cd-footer',
  standalone: true,
  template: `
    <footer class="site-footer">
      <div class="container">
        <div class="cols">
          <div class="col brand-col">
            <img src="assets/logo.svg" alt="chaindora" class="brand-img" />
            <p class="tag-line">
              Supply-chain attack prevention and detection.<br />
              Open source. Apache-2.0. No telemetry.
            </p>
          </div>
          <div class="col">
            <div class="heading">Product</div>
            <a href="#prevention">Prevention (gate)</a>
            <a href="#detection">Detection (scan / audit)</a>
            <a href="#fleet">Fleet mode</a>
            <a href="#install">Install</a>
          </div>
          <div class="col">
            <div class="heading">Docs</div>
            <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/README.md" target="_blank" rel="noopener">README</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/threat-model.md" target="_blank" rel="noopener">Threat model</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/architecture.md" target="_blank" rel="noopener">Architecture</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/ci-integration.md" target="_blank" rel="noopener">CI integration</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/incident-pack.md" target="_blank" rel="noopener">Incident pack</a>
          </div>
          <div class="col">
            <div class="heading">Source</div>
            <a href="https://github.com/alessandro-bitetto/chaindora" target="_blank" rel="noopener">GitHub repo</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/releases" target="_blank" rel="noopener">Releases</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/CHANGELOG.md" target="_blank" rel="noopener">Changelog</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/issues" target="_blank" rel="noopener">Issues</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/SECURITY.md" target="_blank" rel="noopener">Security disclosure</a>
          </div>
        </div>
        <div class="bottom">
          <span>© chaindora contributors. Licensed under Apache-2.0.</span>
          <span class="muted">Not affiliated with any registry.</span>
        </div>
      </div>
    </footer>
  `,
  styles: [
    `
      .site-footer {
        background: #ffffff;
        border-top: 2px solid #000000;
        padding: 64px 0 32px;
        margin-top: 96px;
      }
      .cols {
        display: grid;
        grid-template-columns: 1.5fr 1fr 1fr 1fr;
        gap: 48px;
      }
      .brand-img {
        display: block;
        height: 48px;
        width: auto;
        margin-bottom: 14px;
      }
      .tag-line {
        color: var(--cd-fg-muted);
        font-size: 13px;
        line-height: 1.6;
        margin: 0;
      }
      .heading {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #000000;
        margin-bottom: 12px;
      }
      .col a {
        display: block;
        color: var(--cd-fg);
        font-size: 13px;
        padding: 4px 0;

        &:hover {
          color: var(--cd-accent);
          text-decoration: none;
        }
      }
      .bottom {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-top: 1px solid var(--cd-border);
        padding-top: 24px;
        margin-top: 48px;
        font-size: 12px;
        color: var(--cd-fg-muted);
      }
      @media (max-width: 720px) {
        .cols {
          grid-template-columns: 1fr;
          gap: 32px;
        }
        .bottom {
          flex-direction: column;
          gap: 8px;
          align-items: flex-start;
        }
      }
    `,
  ],
})
export class FooterComponent {}
