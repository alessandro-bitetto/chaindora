import { Routes } from '@angular/router';
import { HomeComponent } from './pages/home/home.component';

export const routes: Routes = [
  { path: '', component: HomeComponent, title: 'Chaindora — Your code. Your rules.' },
  { path: '**', redirectTo: '' },
];
