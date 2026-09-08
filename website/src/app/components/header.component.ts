import { Component, HostListener } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'cd-header',
  standalone: true,
  imports: [RouterLink],
  template: `
    <header class="site-header" [class.scrolled]="scrolled" [class.menu-open]="menuOpen">
      <div class="container nav">
        <a routerLink="/" class="brand" aria-label="chaindora home" (click)="closeMenu()">
          <img src="assets/logo-symbol.png" alt="" class="brand-mark" />
          <span class="brand-text">chaindora</span>
        </a>
        <nav class="links" aria-label="Primary">
          <a href="#prevention">Prevention</a>
          <a href="#detection">Detection</a>
          <a href="#install">Install</a>
          <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/threat-model.md" target="_blank" rel="noopener">Threat model</a>
          <a href="https://github.com/alessandro-bitetto/chaindora" target="_blank" rel="noopener" class="github">GitHub <span aria-hidden="true">→</span></a>
        </nav>
        <button
          type="button"
          class="menu-btn"
          aria-label="Toggle navigation"
          aria-controls="mobile-nav"
          [attr.aria-expanded]="menuOpen"
          (click)="toggleMenu()">
          <span class="bar"></span>
          <span class="bar"></span>
          <span class="bar"></span>
        </button>
      </div>
      @if (menuOpen) {
        <nav id="mobile-nav" class="mobile-nav" aria-label="Primary">
          <div class="container mobile-nav-inner">
            <a href="#prevention" (click)="closeMenu()">Prevention</a>
            <a href="#detection" (click)="closeMenu()">Detection</a>
            <a href="#install" (click)="closeMenu()">Install</a>
            <a href="#fleet" (click)="closeMenu()">Fleet mode</a>
            <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/threat-model.md" target="_blank" rel="noopener" (click)="closeMenu()">Threat model</a>
            <a href="https://github.com/alessandro-bitetto/chaindora" target="_blank" rel="noopener" (click)="closeMenu()">GitHub <span aria-hidden="true">→</span></a>
          </div>
        </nav>
      }
    </header>
  `,
  styles: [
    `
      .site-header {
        background: rgba(255, 255, 255, 0.88);
        backdrop-filter: saturate(140%) blur(10px);
        -webkit-backdrop-filter: saturate(140%) blur(10px);
        border-bottom: 1px solid transparent;
        position: sticky;
        top: 0;
        z-index: 20;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;

        /* Once the page scrolls under the bar, give it an edge so the */
        /* content sliding beneath reads as "behind" the header. */
        &.scrolled,
        &.menu-open {
          border-bottom-color: var(--cd-border);
          box-shadow: 0 1px 0 rgba(0, 0, 0, 0.02), 0 8px 24px rgba(0, 0, 0, 0.06);
        }
      }
      .nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        height: var(--cd-header-h);
      }
      .brand {
        display: flex;
        align-items: center;
        gap: 12px;
        min-width: 0;
        color: #000000 !important;
        &:hover { text-decoration: none; }

        .brand-mark {
          display: block;
          height: 42px;
          width: 42px;
          object-fit: contain;
          flex-shrink: 0;
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
        gap: 4px;
        font-size: 14px;
        flex-shrink: 0;

        a {
          position: relative;
          color: #000000;
          font-weight: 600;
          padding: 8px 12px;
          border-radius: var(--cd-radius);
          transition: color 0.15s ease, background-color 0.15s ease;

          /* Underline that grows in from the center on hover — subtle */
          /* affordance without shifting layout. */
          &::after {
            content: "";
            position: absolute;
            left: 12px;
            right: 12px;
            bottom: 4px;
            height: 2px;
            background: var(--cd-accent);
            border-radius: 2px;
            transform: scaleX(0);
            transition: transform 0.18s ease;
          }
          &:hover {
            color: var(--cd-accent);
            text-decoration: none;
            &::after { transform: scaleX(1); }
          }
        }

        .github {
          margin-left: 12px;
          color: #ffffff;
          background: #000000;
          padding: 8px 16px;
          border-radius: var(--cd-radius);

          &::after { display: none; }
          &:hover {
            background: var(--cd-accent);
            color: #ffffff;
          }
        }
      }

      /* Hamburger — only rendered at phone widths. */
      .menu-btn {
        display: none;
        flex-direction: column;
        justify-content: center;
        gap: 5px;
        width: 44px;
        height: 44px;
        padding: 0 10px;
        margin-right: -8px;
        border: 0;
        border-radius: var(--cd-radius);
        background: transparent;
        cursor: pointer;

        .bar {
          display: block;
          height: 2px;
          width: 100%;
          background: #000000;
          border-radius: 2px;
          transition: transform 0.2s ease, opacity 0.2s ease;
        }
      }
      .menu-open .menu-btn {
        .bar:nth-child(1) { transform: translateY(7px) rotate(45deg); }
        .bar:nth-child(2) { opacity: 0; }
        .bar:nth-child(3) { transform: translateY(-7px) rotate(-45deg); }
      }

      .mobile-nav {
        border-top: 1px solid var(--cd-border);
        background: #ffffff;
      }
      .mobile-nav-inner {
        display: flex;
        flex-direction: column;
        padding-top: 8px;
        padding-bottom: 12px;

        a {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 12px 4px;
          color: #000000;
          font-weight: 600;
          font-size: 16px;
          border-bottom: 1px solid var(--cd-border);

          &:last-child { border-bottom: 0; }
          &:hover { color: var(--cd-accent); text-decoration: none; }
        }
      }

      @media (max-width: 720px) {
        .brand .brand-mark { height: 34px; width: 34px; }
        .brand .brand-text { font-size: 20px; }
        .links a:not(.github) { display: none; }
        .links .github { margin-left: 0; padding: 7px 12px; font-size: 13px; }
        .menu-btn { display: flex; }
      }
    `,
  ],
})
export class HeaderComponent {
  scrolled = false;
  menuOpen = false;

  @HostListener('window:scroll')
  onScroll(): void {
    this.scrolled = window.scrollY > 4;
  }

  @HostListener('window:resize')
  onResize(): void {
    // The desktop nav takes over above 720px — drop the open panel so it
    // doesn't linger when the viewport widens (device rotation, resize).
    if (this.menuOpen && window.innerWidth > 720) {
      this.menuOpen = false;
    }
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    this.closeMenu();
  }

  toggleMenu(): void {
    this.menuOpen = !this.menuOpen;
  }

  closeMenu(): void {
    this.menuOpen = false;
  }
}
