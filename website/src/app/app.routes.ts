import { Routes } from '@angular/router';
import { HomeComponent } from './pages/home/home.component';

export const routes: Routes = [
  { path: '', component: HomeComponent, title: 'Chaindora — Before it lands. After it’s in.' },
  { path: '**', redirectTo: '' },
];
