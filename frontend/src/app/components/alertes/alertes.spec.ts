import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Alertes } from './alertes';

const ALERT = {
  scan_id: 42,
  domain: 'example.test',
  icon: '⚠',
  titre: 'CVE-2026-12345 — example.test',
  message: 'Composant vulnérable.',
  date: '2026-07-30T10:00:00Z',
  niveau: 'CRITIQUE',
  type: 'danger',
  source: 'cve',
  source_id: 'CVE-2026-12345',
  details: {
    source_label: 'Base NVD / CVE',
    identifier: 'CVE-2026-12345',
    fields: [
      { label: 'Score CVSS', value: '8.1/10' },
      {
        label: 'Fiche NVD',
        value: 'CVE-2026-12345',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345',
      },
    ],
    recommendation: 'Mettre le composant à jour.',
  },
};

describe('Alertes', () => {
  let component: Alertes;
  let fixture: ComponentFixture<Alertes>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Alertes],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    fixture = TestBed.createComponent(Alertes);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
    fixture.destroy();
  });

  function loadAlerts(): void {
    const request = httpMock.expectOne('http://127.0.0.1:8000/api/alertes/');
    request.flush({
      alertes: [ALERT],
      stats: { critiques: 1, moyennes: 0, faibles: 0, total: 1 },
    });
    fixture.detectChanges();
  }

  it('loads alerts and their statistics', () => {
    loadAlerts();

    expect(component.alertes).toHaveLength(1);
    expect(component.stats.total).toBe(1);
    expect(fixture.nativeElement.querySelector('.alerte-title').textContent).toContain(
      'CVE-2026-12345',
    );
  });

  it('opens the detail popup on click and closes it with Escape', () => {
    loadAlerts();

    fixture.nativeElement.querySelector('.alerte-item').click();
    fixture.detectChanges();

    const dialog = fixture.nativeElement.querySelector('[role="dialog"]');
    expect(dialog).toBeTruthy();
    expect(dialog.textContent).toContain('Base NVD / CVE');
    expect(dialog.textContent).toContain('8.1/10');
    expect(dialog.textContent).toContain('Mettre le composant à jour.');

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    fixture.detectChanges();

    expect(component.selectedAlerte).toBeNull();
    expect(fixture.nativeElement.querySelector('[role="dialog"]')).toBeNull();
  });
});
