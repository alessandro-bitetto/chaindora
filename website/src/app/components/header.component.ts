import {
  Component,
  ElementRef,
  HostListener,
  NgZone,
  OnDestroy,
  OnInit,
  inject,
} from '@angular/core';
import { NavigationEnd, Router, RouterLink } from '@angular/router';
import { Subscription, filter } from 'rxjs';

interface SectionLink {
  id: 'prevention' | 'detection' | 'install' | 'fleet';
  label: string;
}

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
          @for (s of sections; track s.id) {
            <a
              [href]="'#' + s.id"
              class="section-link"
              [class.active]="active === s.id"
              [attr.aria-current]="active === s.id ? 'true' : null">{{ s.label }}</a>
          }
          <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/threat-model.md" target="_blank" rel="noopener">Threat model</a>
          <a href="https://github.com/alessandro-bitetto/chaindora" target="_blank" rel="noopener" class="github on-dark">GitHub <span aria-hidden="true">→</span></a>
        </nav>
        <button
          type="button"
          class="menu-btn"
          [attr.aria-label]="menuOpen ? 'Close menu' : 'Open menu'"
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
            <div class="mobile-sections">
              @for (s of sections; track s.id) {
                <a
                  [href]="'#' + s.id"
                  class="mobile-section"
                  [class.active]="active === s.id"
                  [attr.aria-current]="active === s.id ? 'true' : null"
                  (click)="closeMenu()">
                  <span class="dot" aria-hidden="true"></span>
                  {{ s.label }}
                </a>
              }
            </div>
            <div class="mobile-external">
              <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/docs/threat-model.md" target="_blank" rel="noopener" (click)="closeMenu()">Threat model</a>
              <a href="https://github.com/alessandro-bitetto/chaindora" target="_blank" rel="noopener" (click)="closeMenu()">GitHub <span aria-hidden="true">→</span></a>
            </div>
          </div>
        </nav>
      }
    </header>
  `,
  styles: [
    `
      /* Sticky lives on the host: a sticky child can only travel within */
      /* its parent's box, and the host is what the page flow sizes.     */
      :host {
        display: block;
        position: sticky;
        top: 0;
        z-index: 20;
      }
      .site-header {
        background: rgba(255, 255, 255, 0.88);
        backdrop-filter: saturate(140%) blur(10px);
        -webkit-backdrop-filter: saturate(140%) blur(10px);
        border-bottom: 1px solid transparent;
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
        gap: 2px;
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
          /* affordance without shifting layout. The same bar stays put */
          /* on the link whose section is currently in view.            */
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
            color: var(--cd-accent-ink);
            text-decoration: none;
            &::after { transform: scaleX(1); }
          }
          &.active {
            color: var(--cd-accent-ink);
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

      /* Compact panel: the four page sections as a 2×2 grid of chips */
      /* with an in-view marker, then the two external links in a row. */
      .mobile-nav {
        border-top: 1px solid var(--cd-border);
        background: #ffffff;
        animation: cd-menu-in 0.18s ease;
      }
      @keyframes cd-menu-in {
        from { opacity: 0; transform: translateY(-6px); }
        to   { opacity: 1; transform: translateY(0); }
      }
      .mobile-nav-inner {
        display: flex;
        flex-direction: column;
        gap: 10px;
        padding-top: 12px;
        padding-bottom: 14px;
      }
      .mobile-sections {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
      }
      .mobile-section {
        display: flex;
        align-items: center;
        gap: 10px;
        min-height: 44px;
        padding: 8px 14px;
        border: 1px solid var(--cd-border);
        border-radius: var(--cd-radius);
        background: var(--cd-bg-elevated);
        color: #000000;
        font-weight: 600;
        font-size: 15px;
        line-height: 1.2;

        .dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: var(--cd-border-strong);
          flex-shrink: 0;
          transition: background-color 0.15s ease, box-shadow 0.15s ease;
        }
        &:hover {
          text-decoration: none;
          border-color: var(--cd-border-strong);
          color: #000000;
        }
        &.active {
          border-color: var(--cd-accent);
          background: var(--cd-accent-soft);
          color: var(--cd-accent-ink);
          .dot {
            background: var(--cd-accent);
            box-shadow: 0 0 0 3px rgba(218, 47, 47, 0.18);
          }
        }
      }
      .mobile-external {
        display: flex;
        gap: 4px 18px;
        flex-wrap: wrap;
        padding: 4px 2px 0;
        border-top: 1px solid var(--cd-border);

        a {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          min-height: 40px;
          color: var(--cd-fg-muted);
          font-weight: 600;
          font-size: 14px;
          &:hover { color: var(--cd-accent-ink); text-decoration: none; }
        }
      }

      @media (max-width: 720px) {
        .brand .brand-mark { height: 34px; width: 34px; }
        .brand .brand-text { font-size: 20px; }
        .links a:not(.github) { display: none; }
        .links .github { margin-left: 0; padding: 7px 12px; font-size: 13px; }
        .menu-btn { display: flex; }
      }
      @media (max-width: 380px) {
        .mobile-sections { grid-template-columns: 1fr; }
      }
    `,
  ],
})
export class HeaderComponent implements OnInit, OnDestroy {
  scrolled = false;
  menuOpen = false;
  // Id of the page section currently under the reading line, or null
  // when none of the anchored sections is (hero, catches, coverage…).
  active: SectionLink['id'] | null = null;

  readonly sections: SectionLink[] = [
    { id: 'prevention', label: 'Prevention' },
    { id: 'detection', label: 'Detection' },
    { id: 'install', label: 'Install' },
    { id: 'fleet', label: 'Fleet mode' },
  ];

  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly router = inject(Router);
  private readonly zone = inject(NgZone);
  private navSub?: Subscription;
  private frame: number | null = null;

  ngOnInit(): void {
    // The sections live in the routed HomeComponent, which renders after
    // this header — recompute once navigation settles (and after each
    // anchor navigation, which also fires NavigationEnd).
    this.navSub = this.router.events
      .pipe(filter((e) => e instanceof NavigationEnd))
      .subscribe(() => this.scheduleUpdate());
    this.scheduleUpdate();
  }

  ngOnDestroy(): void {
    this.navSub?.unsubscribe();
    if (this.frame !== null && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(this.frame);
    }
  }

  @HostListener('window:scroll')
  onScroll(): void {
    this.scrolled = window.scrollY > 4;
    this.scheduleUpdate();
  }

  @HostListener('window:resize')
  onResize(): void {
    // The desktop nav takes over above 720px — drop the open panel so it
    // doesn't linger when the viewport widens (device rotation, resize).
    if (this.menuOpen && window.innerWidth > 720) {
      this.menuOpen = false;
    }
    this.scheduleUpdate();
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    this.closeMenu();
  }

  // Tap outside the header closes the panel — the header is sticky, so
  // the panel would otherwise stay open while the user scrolls the page.
  @HostListener('document:click', ['$event'])
  onDocumentClick(ev: MouseEvent): void {
    if (this.menuOpen && !this.host.nativeElement.contains(ev.target as Node)) {
      this.menuOpen = false;
    }
  }

  toggleMenu(): void {
    this.menuOpen = !this.menuOpen;
  }

  closeMenu(): void {
    this.menuOpen = false;
  }

  // Coalesce scroll/resize bursts into one layout read per frame.
  private scheduleUpdate(): void {
    if (typeof window === 'undefined' || this.frame !== null) {
      return;
    }
    this.frame = requestAnimationFrame(() => {
      this.frame = null;
      this.updateActive();
    });
  }

  // The "reading line" sits a third of the way down the viewport, just
  // below the sticky header. Whichever anchored section straddles that
  // line is current. When two sit side by side (prevention / detection
  // cards on desktop) the one named in the URL hash wins — it is the
  // one the user just navigated to — otherwise the first in page order.
  private updateActive(): void {
    const headerH = this.host.nativeElement.offsetHeight || 72;
    const line = headerH + Math.min(window.innerHeight * 0.3, 240);
    const hits: SectionLink['id'][] = [];
    for (const s of this.sections) {
      const el = document.getElementById(s.id);
      if (!el) {
        continue;
      }
      const r = el.getBoundingClientRect();
      if (r.top <= line && r.bottom > line) {
        hits.push(s.id);
      }
    }
    const fromHash = hits.find((id) => `#${id}` === window.location.hash);
    const next = fromHash ?? hits[0] ?? null;
    if (next !== this.active) {
      // rAF callbacks run outside Angular's zone bookkeeping in some
      // configurations; re-enter so the binding updates immediately.
      this.zone.run(() => (this.active = next));
    }
  }
}
