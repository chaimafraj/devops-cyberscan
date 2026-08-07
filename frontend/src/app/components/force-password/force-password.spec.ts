import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';

import { AuthService } from '../../services/auth.service';
import { ForcePassword } from './force-password';

describe('ForcePassword', () => {
  let component: ForcePassword;
  let fixture: ComponentFixture<ForcePassword>;
  let httpMock: HttpTestingController;
  let authService: AuthService;
  let router: Router;

  beforeEach(async () => {
    sessionStorage.clear();
    sessionStorage.setItem('access_token', 'token');
    sessionStorage.setItem(
      'user',
      JSON.stringify({
        id: 1,
        username: 'test',
        role: 'client',
        must_change_password: true,
      }),
    );

    await TestBed.configureTestingModule({
      imports: [ForcePassword],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(ForcePassword);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    authService = TestBed.inject(AuthService);
    router = TestBed.inject(Router);
    await fixture.whenStable();
  });

  afterEach(() => {
    httpMock.verify();
    sessionStorage.clear();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('clears must_change_password and navigates to dashboard after success', () => {
    const navigateSpy = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    component.oldPassword = 'TempPass123!';
    component.newPassword = 'NewPass123!';
    component.confirmPassword = 'NewPass123!';

    component.submit();

    const req = httpMock.expectOne((r) => r.url.includes('/auth/change-password/'));
    expect(req.request.method).toBe('POST');
    req.flush({
      message: 'Mot de passe modifié avec succès',
      user: {
        id: 1,
        username: 'test',
        role: 'client',
        must_change_password: false,
      },
    });

    expect(authService.getCurrentUser()?.must_change_password).toBe(false);
    expect(navigateSpy).toHaveBeenCalledWith('/dashboard');
  });
});
