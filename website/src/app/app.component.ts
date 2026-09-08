import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './components/header.component';
import { FooterComponent } from './components/footer.component';

@Component({
  selector: 'cd-root',
  standalone: true,
  imports: [RouterOutlet, HeaderComponent, FooterComponent],
  template: `
    <a class="skip-link" href="#main">Skip to content</a>
    <cd-header></cd-header>
    <main id="main" tabindex="-1">
      <router-outlet></router-outlet>
    </main>
    <cd-footer></cd-footer>
  `,
  styles: [
    `
      :host {
        min-height: 100vh;
        display: flex;
        flex-direction: column;
      }
      main {
        flex: 1;
      }
      /* The skip link lands focus here programmatically; the ring on the */
      /* whole page body would be noise, so suppress it for main only.    */
      main:focus {
        outline: none;
        box-shadow: none;
      }
    `,
  ],
})
export class AppComponent {}
