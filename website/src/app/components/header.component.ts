import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'cd-header',
  standalone: true,
  imports: [RouterLink],
  template: `
    <header class="site-header">
      <div class="container nav">
        <a routerLink="/" class="brand" aria-label="chaindora home">
          <img src="assets/logo-symbol.png" alt="" class="brand-mark" />
          <span class="brand-text">chaindora</span>
        </a>
        <nav class="links">
          <a href="#prevention">Prevention</a>
          <a href="#detection">Detection</a>
          <a href="#install">Install</a>
          <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/threat-model.md" target="_blank" rel="noopener">Threat model</a>
          <a href="https://github.com/alessandro-bitetto/chaindora" target="_blank" rel="noopener" class="github">GitHub →</a>
        </nav>
      </div>
    </header>
  `,
  styles: [
    `
      .site-header {
        background: rgba(255, 255, 255, 0.92);
        backdrop-filter: saturate(140%) blur(8px);
        -webkit-backdrop-filter: saturate(140%) blur(8px);
        border-bottom: 1px solid var(--cd-border);
        position: sticky;
        top: 0;
        z-index: 10;
      }
      .nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        height: 72px;
      }
      .brand {
        display: flex;
        align-items: center;
        gap: 12px;
        color: #000000 !important;
        &:hover { text-decoration: none; }

        .brand-mark {
          display: block;
          height: 44px;
          width: 44px;
          object-fit: contain;
        }
        .brand-text {
          font-family: var(--cd-display);
          font-weight: 400;
          font-size: 24px;
          letter-spacing: 0.01em;
          line-height: 1;
        }
      }
      .links {
        display: flex;
        align-items: center;
        gap: 28px;
        font-size: 14px;

        a {
          color: #000000;
          font-weight: 600;
          &:hover {
            color: var(--cd-accent);
            text-decoration: none;
          }
        }

        .github {
          color: #ffffff;
          background: #000000;
          padding: 7px 14px;
          border-radius: var(--cd-radius);

          &:hover {
            background: var(--cd-accent);
            color: #ffffff;
          }
        }
      }
      @media (max-width: 720px) {
        .links a:not(.github) {
          display: none;
        }
      }
    `,
  ],
})
export class HeaderComponent {}
