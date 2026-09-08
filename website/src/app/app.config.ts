import {
  APP_INITIALIZER,
  ApplicationConfig,
  inject,
  provideZoneChangeDetection,
} from '@angular/core';
import { ViewportScroller } from '@angular/common';
import { provideRouter, withInMemoryScrolling } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { routes } from './app.routes';

// The router's anchor scrolling positions a fragment target with
// window.scrollTo(), which ignores CSS scroll-padding — so without an
// explicit offset every "#install"-style link parks the section heading
// underneath the sticky header. The offset is read live from the header
// so it tracks the 72px / 60px desktop-mobile heights automatically.
function configureAnchorOffset(): () => void {
  const scroller = inject(ViewportScroller);
  return () => {
    scroller.setOffset(() => {
      const header =
        typeof document !== 'undefined'
          ? (document.querySelector('cd-header') as HTMLElement | null)
          : null;
      return [0, (header?.offsetHeight ?? 72) + 16];
    });
  };
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideHttpClient(),
    provideRouter(
      routes,
      withInMemoryScrolling({
        scrollPositionRestoration: 'enabled',
        anchorScrolling: 'enabled',
      }),
    ),
    { provide: APP_INITIALIZER, useFactory: configureAnchorOffset, multi: true },
  ],
};
