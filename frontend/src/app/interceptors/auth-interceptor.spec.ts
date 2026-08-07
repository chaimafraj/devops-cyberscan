import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { ScannerService } from '../services/scanner.service';
import { authInterceptor } from './auth-interceptor';

describe('authInterceptor', () => {
  let scanner: ScannerService;
  let http: HttpTestingController;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    scanner = TestBed.inject(ScannerService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    sessionStorage.clear();
    http.verify();
  });

  it('refreshes an expired access token and retries the scan request once', () => {
    sessionStorage.setItem('access_token', 'expired-access');
    sessionStorage.setItem('refresh_token', 'valid-refresh');

    let response: unknown;
    scanner.demarrerScan('example.com', { zap: true }).subscribe((value) => (response = value));

    const initial = http.expectOne('/api/scans/');
    expect(initial.request.headers.get('Authorization')).toBe('Bearer expired-access');
    initial.flush(
      { detail: 'Given token not valid for any token type' },
      { status: 401, statusText: 'Unauthorized' },
    );

    const refresh = http.expectOne('/api/auth/refresh/');
    expect(refresh.request.method).toBe('POST');
    expect(refresh.request.headers.has('Authorization')).toBe(false);
    expect(refresh.request.body).toEqual({ refresh: 'valid-refresh' });
    refresh.flush({ access: 'fresh-access' });

    const retried = http.expectOne('/api/scans/');
    expect(retried.request.headers.get('Authorization')).toBe('Bearer fresh-access');
    retried.flush({ success: true, scans: [] });

    expect(sessionStorage.getItem('access_token')).toBe('fresh-access');
    expect(response).toEqual({ success: true, scans: [] });
  });

  it('clears the stale session when the refresh token is rejected', () => {
    sessionStorage.setItem('access_token', 'expired-access');
    sessionStorage.setItem('refresh_token', 'expired-refresh');
    sessionStorage.setItem('user', JSON.stringify({ username: 'administrateur' }));

    scanner.getRecentScans().subscribe({ error: () => undefined });

    http.expectOne('/api/scans/').flush(
      { detail: 'Given token not valid for any token type' },
      { status: 401, statusText: 'Unauthorized' },
    );
    http.expectOne('/api/auth/refresh/').flush(
      { detail: 'Token is invalid or expired' },
      { status: 401, statusText: 'Unauthorized' },
    );

    expect(sessionStorage.getItem('access_token')).toBeNull();
    expect(sessionStorage.getItem('refresh_token')).toBeNull();
    expect(sessionStorage.getItem('user')).toBeNull();
  });
});
