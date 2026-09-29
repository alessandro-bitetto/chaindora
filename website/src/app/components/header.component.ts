import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
@Component({
  selector: 'cd-header', standalone: true, imports: [RouterLink],
  template: `
    <a class="skip-link" routerLink="/" fragment="main-content">Skip to content</a>
    <header class="site-header"><div class="container nav">
      <a routerLink="/" class="brand" aria-label="Chaindora home"><img src="assets/logo-symbol.png" alt="" width="48" height="46"><span>chaindora<span class="brand-period">.</span></span></a>
      <button type="button" class="menu-button" [attr.aria-expanded]="open" aria-controls="site-navigation" (click)="open = !open">{{ open ? 'Close −' : 'Menu +' }}</button>
      <nav id="site-navigation" aria-label="Main navigation" [class.open]="open">
        <a routerLink="/" fragment="protection" (click)="open = false">Protection</a><a routerLink="/" fragment="ecosystems" (click)="open = false">Ecosystems</a>
        <a href="https://github.com/alessandro-bitetto/chaindora/blob/main/README.md">Docs ↗</a>
        <a routerLink="/" fragment="install" class="nav-cta" (click)="open = false">Get Chaindora <span aria-hidden="true">↗</span></a>
      </nav>
    </div></header>`,
  styles: [`
    :host { display: block; position: sticky; top: 0; z-index: 20; }
    .skip-link { position: fixed; left: 15px; top: -100px; z-index: 30; background: #000; color: #fff; padding: 12px 18px; }.skip-link:focus { top: 12px; }
    .site-header { background: #fff; border-bottom: 1px solid var(--cd-line); }
    .nav { min-height: 87px; display: flex; align-items: center; justify-content: space-between; gap: 24px; }
    .brand { display: flex; align-items: center; gap: 4px; }.brand img { object-fit: contain; }.brand > span { font-family: var(--cd-display); font-size: 24px; letter-spacing: -.05em; }.brand-period { color: var(--cd-red); }
    nav { display: flex; align-items: center; gap: 34px; font-size: 12px; font-weight: 600; }nav > a:hover { color: var(--cd-red); }
    .nav-cta { background: #000; color: #fff; padding: 11px 18px; display: flex; align-items: center; gap: 23px; }nav .nav-cta:hover { background: var(--cd-red); color: #fff; }
    .menu-button { display: none; background: none; border: 1px solid var(--cd-line); padding: 8px 13px; font: 11px var(--cd-mono); }
    @media(max-width: 680px) { .nav { min-height: 69px; flex-wrap: wrap; column-gap: 15px; }.brand > span { font-size: 21px; }.brand img { width: 40px; height: 39px; }.menu-button { display: block; }nav { display: none; flex-basis: 100%; flex-wrap: wrap; align-items: center; gap: 24px; padding-bottom: 20px; }nav.open { display: flex; }.nav-cta { padding: 8px 13px; gap: 12px; } }
  `],
})
export class HeaderComponent { open = false; }
