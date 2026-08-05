import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { ScannerService } from './scanner.service';

describe('ScannerService', () => {
  let service: ScannerService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ScannerService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('calls the cancellation endpoint for the active scan', () => {
    let status = '';

    service.cancelScan(42).subscribe((response) => (status = response.status));
    const request = http.expectOne('http://127.0.0.1:8000/api/scans/42/cancel/');

    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({});
    request.flush({ scan_id: 42, status: 'CANCELLED', message: 'Scan annulé.' });
    expect(status).toBe('CANCELLED');
  });

  it('downloads the report QR code as an SVG blob', () => {
    service.getReportQr(176).subscribe();

    const request = http.expectOne(
      'http://127.0.0.1:8000/api/scans/176/rapport/qr/',
    );
    expect(request.request.method).toBe('GET');
    expect(request.request.responseType).toBe('blob');
    request.flush(new Blob(['<svg></svg>'], { type: 'image/svg+xml' }));
  });
});
