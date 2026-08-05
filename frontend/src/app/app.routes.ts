import { Routes } from '@angular/router';
import { authGuard } from './guards/auth-guard';

export const routes: Routes = [
  { path: '', redirectTo: 'login', pathMatch: 'full' },
  {
    path: 'login',
    loadComponent: () => import('./components/login/login').then((m) => m.Login),
  },
  {
    path: 'force-password',
    loadComponent: () =>
      import('./components/force-password/force-password').then((m) => m.ForcePassword),
    canActivate: [authGuard],
  },
  {
    path: 'dashboard',
    loadComponent: () => import('./components/dashboard/dashboard').then((m) => m.Dashboard),
    canActivate: [authGuard],
  },
  {
    path: 'scanner',
    loadComponent: () => import('./components/scanner/scanner').then((m) => m.Scanner),
    canActivate: [authGuard],
  },
  {
    path: 'historique',
    loadComponent: () => import('./components/historique/historique').then((m) => m.Historique),
    canActivate: [authGuard],
  },
  {
    path: 'alertes',
    loadComponent: () => import('./components/alertes/alertes').then((m) => m.Alertes),
    canActivate: [authGuard],
  },
  {
    path: 'profile',
    loadComponent: () => import('./components/profile/profile').then((m) => m.Profile),
    canActivate: [authGuard],
  },

  {
    path: 'clients',
    loadComponent: () =>
      import('./components/gestion-clients/gestion-clients').then((m) => m.GestionClients),
    canActivate: [authGuard],
  },
  { path: '**', redirectTo: 'login' },
];
