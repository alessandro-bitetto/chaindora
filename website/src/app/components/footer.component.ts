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
        position: relative;
        background: #ffffff;
        border-top: 1px solid var(--cd-border);
        padding: clamp(48px, 6vw, 72px) 0 32px;

        /* Thin brand rule sitting on the top border — echoes the red */
        /* accents used by the section eyebrows above. */
        &::before {
          content: "";
          position: absolute;
          top: -1px;
          left: 50%;
          transform: translateX(-50%);
          width: min(120px, 30%);
          height: 3px;
          background: var(--cd-accent);
          border-radius: 0 0 3px 3px;
        }
      }
      .cols {
        display: grid;
        grid-template-columns: minmax(0, 1.6fr) repeat(3, minmax(0, 1fr));
        gap: 40px 48px;
      }
      .brand-img {
        display: block;
        height: 44px;
        width: auto;
        margin-bottom: 16px;
      }
      .tag-line {
        color: var(--cd-fg-muted);
        font-size: 14px;
        line-height: 1.6;
        margin: 0;
      }
      .heading {
        font-family: var(--cd-mono);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: #000000;
        margin-bottom: 14px;
      }
      .col a {
        display: block;
        color: var(--cd-fg-muted);
        font-size: 14px;
        padding: 5px 0;
        transition: color 0.15s ease, transform 0.15s ease;

        &:hover {
          color: var(--cd-accent);
          text-decoration: none;
          transform: translateX(2px);
        }
      }
      .bottom {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
        border-top: 1px solid var(--cd-border);
        padding-top: 24px;
        margin-top: clamp(32px, 5vw, 56px);
        font-size: 13px;
        color: var(--cd-fg-muted);
      }
      @media (max-width: 900px) {
        .cols {
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 36px 32px;
        }
        .brand-col { grid-column: 1 / -1; }
      }
      @media (max-width: 560px) {
        .cols {
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 32px 24px;
        }
        .bottom {
          flex-direction: column;
          align-items: flex-start;
          gap: 6px;
        }
      }
    `,
  ],
})
export class FooterComponent {}
