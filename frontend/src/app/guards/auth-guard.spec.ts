import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';

import { AuthService } from '../services/auth.service';
import { authGuard } from './auth-guard';

describe('authGuard', () => {
  afterEach(() => {
    sessionStorage.clear();
  });

  function setup(user: Record<string, unknown> | null, token = 'token') {
    sessionStorage.clear();
    if (token) sessionStorage.setItem('access_token', token);
    if (user) sessionStorage.setItem('user', JSON.stringify(user));

    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [provideRouter([])],
    });

    return {
      authService: TestBed.inject(AuthService),
      router: TestBed.inject(Router),
    };
  }

  it('redirects authenticated users with must_change_password to force-password', () => {
    const { router } = setup({
      id: 1,
      username: 'test',
      must_change_password: true,
    });
    const navigateSpy = vi.spyOn(router, 'navigate');

    const result = TestBed.runInInjectionContext(() =>
      authGuard({} as any, { url: '/dashboard' } as any),
    );

    expect(result).toBe(false);
    expect(navigateSpy).toHaveBeenCalledWith(['/force-password']);
  });

  it('allows dashboard when must_change_password is false', () => {
    setup({
      id: 1,
      username: 'test',
      must_change_password: false,
    });

    const result = TestBed.runInInjectionContext(() =>
      authGuard({} as any, { url: '/dashboard' } as any),
    );

    expect(result).toBe(true);
  });
});
