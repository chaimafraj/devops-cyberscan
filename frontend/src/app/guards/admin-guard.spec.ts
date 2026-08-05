import { TestBed } from '@angular/core/testing';
import { CanActivateFn, provideRouter, Router, UrlTree } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { adminGuard } from './admin-guard';

describe('adminGuard', () => {
  const authService = { isAdmin: vi.fn() };
  const executeGuard: CanActivateFn = (...parameters) =>
    TestBed.runInInjectionContext(() => adminGuard(...parameters));

  beforeEach(() => {
    authService.isAdmin.mockReset();
    TestBed.configureTestingModule({
      providers: [provideRouter([]), { provide: AuthService, useValue: authService }],
    });
  });

  it('allows administrators', () => {
    authService.isAdmin.mockReturnValue(true);
    expect(executeGuard({} as never, {} as never)).toBe(true);
  });

  it('returns a redirect UrlTree for non-administrators', () => {
    authService.isAdmin.mockReturnValue(false);
    const result = executeGuard({} as never, {} as never);
    expect(result).toBeInstanceOf(UrlTree);
    expect(TestBed.inject(Router).serializeUrl(result as UrlTree)).toBe('/dashboard');
  });
});
