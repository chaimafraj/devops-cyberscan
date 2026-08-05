import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NEVER, of } from 'rxjs';

import { ScannerService } from '../../services/scanner.service';
import { Scanner } from './scanner';

describe('Scanner', () => {
  let component: Scanner;
  let fixture: ComponentFixture<Scanner>;

  beforeEach(async () => {
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue({
      fillStyle: '',
      font: '',
      fillRect: vi.fn(),
      fillText: vi.fn(),
    } as unknown as CanvasRenderingContext2D);

    await TestBed.configureTestingModule({
      imports: [Scanner],
    }).compileComponents();

    fixture = TestBed.createComponent(Scanner);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should not display Nuclei as a scan option', () => {
    expect(component.options.some((option) => option.id === 'nuclei')).toBeFalsy();
  });

  it('should keep the progress state while an asynchronous scan is queued', () => {
    const scannerService = TestBed.inject(ScannerService);
    vi.spyOn(scannerService, 'demarrerScan').mockReturnValue(of({
      scans: [{
        scan_id: 42,
        task_id: 'task-42',
        domaine: 'google.com',
        status: 'PENDING',
        status_url: '/api/scans/42/',
      }],
      tracking_ids: [42],
    }));
    vi.spyOn(scannerService, 'getScan').mockReturnValue(NEVER);
    component.targetUrl = 'google.com';

    component.lancerScan();

    expect(component.scanning).toBe(true);
    expect(component.scanStatus).toBe('PENDING');
    expect(component.scanResult).toBeNull();
  });

  it('cancels the queued scan and stops the progress state', () => {
    const scannerService = TestBed.inject(ScannerService);
    vi.spyOn(scannerService, 'demarrerScan').mockReturnValue(of({
      scans: [{
        scan_id: 77,
        task_id: 'task-77',
        domaine: 'google.com',
        status: 'PENDING',
        status_url: '/api/scans/77/',
      }],
      tracking_ids: [77],
    }));
    vi.spyOn(scannerService, 'getScan').mockReturnValue(NEVER);
    vi.spyOn(scannerService, 'cancelScan').mockReturnValue(of({
      scan_id: 77,
      status: 'CANCELLED',
      message: 'Scan annulé.',
    }));
    component.targetUrl = 'google.com';
    component.lancerScan();

    component.annulerScan();

    expect(scannerService.cancelScan).toHaveBeenCalledWith(77);
    expect(component.scanning).toBe(false);
    expect(component.scanStatus).toBe('CANCELLED');
    expect(component.cancelMessage).toContain('annulé');
  });
  it('hides the tools list after completion until a new scan is requested', async () => {
    (component as any).displayCompletedScan({
      id: 91,
      domaine: 'google.com',
      score_risque_ia: 2,
      protocols: [],
      vulnerabilities: [],
    }, 'google.com', false);
    await fixture.whenStable();

    expect(component.scanResult).not.toBeNull();
    expect(fixture.nativeElement.querySelector('.options-grid')).toBeNull();
    expect(fixture.nativeElement.querySelector('.result-actions')).not.toBeNull();

    component.nouveauScan();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(component.scanResult).toBeNull();
    expect(component.scanStatus).toBe('IDLE');
    expect(fixture.nativeElement.querySelector('.options-grid')).not.toBeNull();
  });});
