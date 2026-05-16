import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { HeaderComponent } from './components/header.component';
import { FooterComponent } from './components/footer.component';

@Component({
  selector: 'cd-root',
  standalone: true,
  imports: [RouterOutlet, HeaderComponent, FooterComponent],
  template: `
    <cd-header></cd-header>
    <main>
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
export class AppComponent {}
