import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { MatPaginator } from '@angular/material/paginator';
import { By } from '@angular/platform-browser';

import { Historique } from './historique';

describe('Historique', () => {
  let component: Historique;
  let fixture: ComponentFixture<Historique>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Historique],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    fixture = TestBed.createComponent(Historique);
    component = fixture.componentInstance;
    httpMock = TestBed.inject(HttpTestingController);
    await fixture.whenStable();

    const initReq = httpMock.expectOne((request) => request.url === '/api/scans/');
    initReq.flush({ results: [], total: 0, total_pages: 1, page: 1 });
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should load scans without search parameter when search is empty', () => {
    component.search = '';

    component.loadScans();

    const req = httpMock.expectOne((request) => request.url === '/api/scans/');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('10');
    expect(req.request.params.has('search')).toBe(false);

    req.flush({ results: [], total: 0, total_pages: 1, page: 1 });
  });

  it('separates the risk level from the scan status', () => {
    component.loadScans();

    const req = httpMock.expectOne((request) => request.url === '/api/scans/');
    req.flush({
      results: [
        { id: 1, score_risque_ia: 2, status: 'COMPLETED' },
        { id: 2, score_risque_ia: 5, status: 'RUNNING' },
        { id: 3, score_risque_ia: 8, status: 'FAILED' },
      ],
      total: 3,
      total_pages: 1,
      page: 1,
    });

    expect(component.displayedColumns).toContain('risk');
    expect(component.displayedColumns).toContain('statut');
    expect(component.displayedColumns).toContain('actions');
    expect(component.displayedColumns).not.toContain('exports');
    expect(component.scans.map((scan) => scan.statut)).toEqual(['FAIBLE', 'MOYEN', 'ÉLEVÉ']);
    expect(component.getScanStatusLabel(component.scans[0].status)).toBe('TERMINÉ');
    expect(component.getScanStatusLabel(component.scans[1].status)).toBe('EN COURS');
    expect(component.getScanStatusLabel(component.scans[2].status)).toBe('ÉCHEC');
  });

  it('builds the professional detail view from the real scan response', () => {
    component.viewScan({
      id: 176,
      domaine: 'audit.example',
      date_scan: '2026-08-03T10:00:00Z',
      score_risque_ia: 8.2,
      status: 'COMPLETED',
      resultats_ssl: {},
    });

    const detailRequest = httpMock.expectOne('/api/scans/176/');
    const manualRequest = httpMock.expectOne(
      '/api/scans/176/vulnerabilites/',
    );

    detailRequest.flush({
      id: 176,
      domaine: 'audit.example',
      client_nom: 'Client test',
      date_scan: '2026-08-03T10:00:00Z',
      score_risque_ia: 8.2,
      status: 'COMPLETED',
      duration_seconds: 18.4,
      report_status: 'pret',
      email_status: 'envoye',
      timeline: [
        { type: 'scan.completed', label: 'Scan termine', timestamp: '2026-08-03T10:00:18Z' },
      ],
      cves: [{
        cve_id: 'CVE-2026-12345',
        cvss_score: 9.8,
        produit_concerne: 'Django',
        description: 'Correctif requis',
        recommandation_ia: 'Mettre a jour Django',
      }],
      resultats_ssl: {
        sslscan: 'TLSv1.2 enabled',
        protocols: [{ name: 'TLSv1.2', status: 'secure' }],
        cipher_suites: [{ name: 'TLS_AES_256_GCM_SHA384' }],
        ports: [{ port: 443, protocol: 'tcp', service: 'https' }],
        whatweb: { success: true, technologies: [{ name: 'Django', version: ['5.0'] }] },
        tool_executions: {
          sslscan: {
            success: true,
            duration_seconds: 1.2,
            completed_at: '2026-08-03T10:00:01Z',
          },
        },
        nuclei_requested: true,
        nuclei_success: true,
        nuclei_findings: [{
          template_id: 'exposed-admin-panel',
          name: 'Exposed administration panel',
          severity: 'high',
          description: 'Administration panel reachable from the Internet.',
          matched_at: 'https://audit.example/admin',
          remediation: 'Restrict access to trusted networks.',
        }],
      },
    });
    manualRequest.flush([]);

    expect(component.selectedScan.executiveSummary).toContain('audit.example');
    expect(component.selectedScan.durationLabel).toBe('18 s');
    expect(component.selectedScan.reportStatusLabel).toBe('Rapport disponible');
    expect(component.selectedScan.emailStatusLabel).toBe('E-mail envoy\u00e9');
    expect(component.selectedScan.primaryFinding.cve).toBe('CVE-2026-12345');
    expect(component.selectedScan.technologiesUi[0].name).toBe('Django');
    expect(component.selectedScan.toolsUi.find((tool: any) => tool.key === 'sslscan').statusKey)
      .toBe('completed');
    expect(component.selectedScan.nucleiFindingsUi[0].templateId).toBe('exposed-admin-panel');
    expect(component.selectedScan.nucleiFindingsUi[0].target).toBe('https://audit.example/admin');
    expect(component.selectedScan.allFindings.some((finding: any) => finding.source === 'NUCLEI'))
      .toBe(true);
  });
  it('should refresh paginator bindings after the scans response', () => {
    component.loadScans();

    const req = httpMock.expectOne((request) => request.url === '/api/scans/');
    req.flush({ results: [], total: 4, total_pages: 1, page: 1 });

    const paginator = fixture.debugElement.query(By.directive(MatPaginator))
      .componentInstance as MatPaginator;

    expect(paginator.length).toBe(4);
    expect(paginator.disabled).toBe(false);
  });
});
