import { Component, inject } from '@angular/core';
import { ViewportScroller } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './components/header.component';
import { FooterComponent } from './components/footer.component';

@Component({
  selector: 'cd-root',
  standalone: true,
  imports: [RouterOutlet, HeaderComponent, FooterComponent],
  template: `
    <cd-header></cd-header>
    <main id="main-content">
      <router-outlet></router-outlet>
    </main>
    <cd-footer></cd-footer>
  `,
  styles: [
    `
      :host {
        display: block;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
      }
      main {
        flex: 1;
      }
    `,
  ],
})
export class AppComponent {
  constructor() {
    inject(ViewportScroller).setOffset(() => [
      0, (document.querySelector('cd-header')?.getBoundingClientRect().height ?? 88) + 16,
    ]);
  }
}
