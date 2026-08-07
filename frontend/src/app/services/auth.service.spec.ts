import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';

import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideRouter([])],
    });
    service = TestBed.inject(AuthService);
  });

  afterEach(() => {
    sessionStorage.clear();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('updates must_change_password in memory and sessionStorage', () => {
    sessionStorage.setItem(
      'user',
      JSON.stringify({ id: 1, username: 'test', must_change_password: true }),
    );
    (service as any).currentUserSubject.next({
      id: 1,
      username: 'test',
      must_change_password: true,
    });

    service.updateCurrentUser({ must_change_password: false });

    expect(service.getCurrentUser()?.must_change_password).toBe(false);
    expect(JSON.parse(sessionStorage.getItem('user') || '{}').must_change_password).toBe(false);
  });
});
