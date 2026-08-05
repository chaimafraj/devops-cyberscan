import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (!authService.isLoggedIn()) {
    router.navigate(['/login']);
    return false;
  }

  const user = authService.getCurrentUser();
  const mustChange = user?.must_change_password === true;

  if (mustChange && state.url !== '/force-password') {
    router.navigate(['/force-password']);
    return false;
  }

  if (!mustChange && state.url === '/force-password') {
    router.navigate(['/dashboard']);
    return false;
  }

  return true;
};
