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

  it('updates must_change_password in memory, signal and sessionStorage', () => {
    service.setCurrentUser({
      id: 1,
      username: 'test',
      must_change_password: true,
    });

    service.updateCurrentUser({ must_change_password: false });

    expect(service.getCurrentUser()?.must_change_password).toBe(false);
    expect(service.currentUser()?.must_change_password).toBe(false);
    expect(JSON.parse(sessionStorage.getItem('user') || '{}').must_change_password).toBe(false);
  });

  it('exposes login user on the signal without requiring a page refresh', () => {
    service.setCurrentUser({ id: 2, username: 'admin', role: 'admin' });

    expect(service.currentUser()?.username).toBe('admin');
    expect(service.isLoggedIn()).toBe(true);
  });
});
