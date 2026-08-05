import { Component, OnInit, OnDestroy, ViewEncapsulation, ChangeDetectorRef } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpParams } from '@angular/common/http';
import { MatTableDataSource, MatTableModule } from '@angular/material/table';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { AuthService } from '../../services/auth.service';
import { ScannerService } from '../../services/scanner.service';
import { ExportService } from '../../services/export.service';
import { ToastService } from '../../services/toast.service';
import { ChatbotContextService } from '../../services/chatbot-context.service';
import { VulnManuelleForm } from '../vuln-manuelle-form/vuln-manuelle-form';

@Component({
  selector: 'app-historique',
  imports: [FormsModule, CommonModule, MatTableModule, MatPaginatorModule, VulnManuelleForm],
  templateUrl: './historique.html',
  styleUrl: './historique.scss',
  standalone: true,
  encapsulation: ViewEncapsulation.None,
})
class Historique implements OnInit, OnDestroy {
  search = '';
  filterRisk = '';
  scans: any[] = [];
  dataSource = new MatTableDataSource<any>([]);
  displayedColumns: string[] = [];
  isAdmin = false;
  selectedScan: any = null;
  selectedProtocol: any = null;
  editMode = false;
  editDomaine = '';
  loading = true;
  detailLoading = false;
  detailError = '';
  qrCodeUrl: string | null = null;
  qrLoading = false;
  relaunching = false;

  vulnsManuelles: any[] = [];
  showVulnForm = false;

  /** Messages UI (succès / erreur) pour PDF et email */
  actionMessage: { type: 'success' | 'error'; text: string } | null = null;
  private actionMessageTimer: ReturnType<typeof setTimeout> | null = null;

  currentPage = 1;
  pageSize = 10;
  totalPages = 1;
  total = 0;

  private matrixInterval: any;
  private apiUrl = 'http://127.0.0.1:8000/api';

  constructor(
    private http: HttpClient,
    private authService: AuthService,
    private scannerService: ScannerService,
    private exportService: ExportService,
    private toastService: ToastService,
    private chatbotContext: ChatbotContextService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit() {
    this.isAdmin = this.authService.getUserRole() === 'admin';
    this.displayedColumns = this.isAdmin
      ? ['client', 'domaine', 'date', 'protocols', 'score', 'risk', 'statut', 'rapport', 'email', 'actions']
      : ['domaine', 'date', 'protocols', 'score', 'risk', 'statut', 'rapport', 'email', 'actions'];
    this.chatbotContext.clearScanContext();
    this.startMatrix();
    this.loadScans();

    const linkedScanId = Number(new URLSearchParams(window.location.search).get('scan'));
    if (Number.isInteger(linkedScanId) && linkedScanId > 0) {
      this.viewScan({
        id: linkedScanId,
        domaine: '',
        date_scan: null,
        score_risque_ia: 0,
        status: 'PENDING',
        resultats_ssl: {},
      });
    }
  }

  ngOnDestroy() {
    if (this.matrixInterval) clearInterval(this.matrixInterval);
    if (this.actionMessageTimer) clearTimeout(this.actionMessageTimer);
    this.revokeQrCodeUrl();
    this.chatbotContext.clearScanContext();
  }

  loadScans(page = 1) {
    this.loading = true;
    const search = this.search.trim();
    let params = new HttpParams().set('page', page).set('page_size', this.pageSize);

    if (search) params = params.set('search', search);
    if (this.filterRisk) params = params.set('risk', this.filterRisk.toUpperCase());

    this.http.get<any>(`${this.apiUrl}/scans/`, { params }).subscribe({
      next: (data) => {
        const list = Array.isArray(data) ? data : (data.results ?? []);
        this.total = data.total ?? data.count ?? list.length;
        this.totalPages = data.total_pages ?? Math.max(1, Math.ceil(this.total / this.pageSize));
        this.currentPage = data.page ?? page;

        this.scans = list.map((s: any) => this.mapScanUi(s));
        this.dataSource.data = this.scans;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('API Error:', err);
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  /** Enrichit un scan avec les champs d'interface PDF / email */
  private mapScanUi(s: any) {
    const pdfReady = !!(s.pdf_disponible ?? s.has_rapport);
    return {
      ...s,
      riskClass: s.score_risque_ia >= 7 ? 'danger' : s.score_risque_ia >= 4 ? 'warn' : 'ok',
      statut: s.score_risque_ia >= 7 ? 'ÉLEVÉ' : s.score_risque_ia >= 4 ? 'MOYEN' : 'FAIBLE',
      // Statuts rapport : non_genere | generation | pret | erreur
      rapportStatus:
        s.rapport_status ?? s.rapportStatus ?? (pdfReady ? 'pret' : 'non_genere'),
      // Statuts email : non_envoye | envoi | envoye | erreur
      emailStatus: s.email_status ?? s.emailStatus ?? 'non_envoye',
      pdfGenerating: false,
      pdfDownloading: false,
      emailSending: false,
    };
  }

  getScanStatusLabel(status: unknown): string {
    switch (String(status ?? '').toUpperCase()) {
      case 'COMPLETED':
        return 'TERMINÉ';
      case 'RUNNING':
        return 'EN COURS';
      case 'PENDING':
        return 'EN ATTENTE';
      case 'FAILED':
        return 'ÉCHEC';
      case 'CANCELLED':
        return 'ANNULÉ';
      default:
        return 'INCONNU';
    }
  }

  getScanStatusClass(status: unknown): string {
    switch (String(status ?? '').toUpperCase()) {
      case 'COMPLETED':
        return 'ok';
      case 'RUNNING':
      case 'PENDING':
        return 'warn';
      default:
        return 'danger';
    }
  }

  getRapportStatusLabel(status: string): string {
    switch (status) {
      case 'generation':
        return 'En cours';
      case 'pret':
        return 'Rapport disponible';
      case 'erreur':
        return 'Rapport indisponible';
      default:
        return 'Rapport indisponible';
    }
  }

  getEmailStatusLabel(status: string): string {
    switch (status) {
      case 'envoi':
        return 'En attente';
      case 'envoye':
        return 'E-mail envoy\u00e9';
      case 'erreur':
        return '\u00c9chec';
      default:
        return 'En attente';
    }
  }
  showActionMessage(type: 'success' | 'error', text: string) {
    if (this.actionMessageTimer) clearTimeout(this.actionMessageTimer);
    this.actionMessage = { type, text };
    this.actionMessageTimer = setTimeout(() => {
      this.actionMessage = null;
      this.actionMessageTimer = null;
      this.cdr.detectChanges();
    }, 4000);
    this.cdr.detectChanges();
  }

  clearActionMessage() {
    if (this.actionMessageTimer) clearTimeout(this.actionMessageTimer);
    this.actionMessage = null;
  }

  private refreshScanRow(scan: any) {
    this.dataSource.data = [...this.scans];
    this.cdr.detectChanges();
  }

  private extractErrorMessage(err: any, fallback: string): string {
    const body = err?.error;
    if (!body) return fallback;
    if (typeof body === 'string') return body;
    if (body.error) return String(body.error);
    if (body.detail) return String(body.detail);
    if (body.message) return String(body.message);
    return fallback;
  }

  private async blobErrorMessage(err: any, fallback: string): Promise<string> {
    try {
      if (err?.error instanceof Blob) {
        const text = await err.error.text();
        const parsed = JSON.parse(text);
        return parsed.error || parsed.detail || parsed.message || fallback;
      }
    } catch {
      /* ignore parse errors */
    }
    return this.extractErrorMessage(err, fallback);
  }

  /**
   * Génère si besoin puis télécharge le rapport PDF via l'API.
   * GET /api/scans/:id/rapport/download/
   */
  telechargerRapportPdf(scan: any, event?: Event) {
    event?.stopPropagation();
    if (scan.pdfGenerating || scan.pdfDownloading) return;

    this.clearActionMessage();
    scan.pdfGenerating = true;
    scan.rapportStatus = 'generation';
    this.refreshScanRow(scan);

    this.scannerService.downloadRapportPdf(scan.id).subscribe({
      next: (blob) => {
        scan.pdfGenerating = false;

        if (!(blob instanceof Blob) || blob.size === 0) {
          scan.rapportStatus = 'erreur';
          scan.pdfDownloading = false;
          this.showActionMessage('error', `Rapport PDF vide pour ${scan.domaine}.`);
          this.refreshScanRow(scan);
          return;
        }

        // Erreur JSON renvoyée en blob (ex. 500)
        if (blob.type && blob.type.includes('application/json')) {
          blob.text().then((text) => {
            let msg = `Échec du téléchargement du rapport PDF pour ${scan.domaine}.`;
            try {
              const parsed = JSON.parse(text);
              msg = parsed.error || parsed.detail || msg;
            } catch {
              /* keep default */
            }
            scan.rapportStatus = 'erreur';
            scan.pdfDownloading = false;
            this.showActionMessage('error', msg);
            this.refreshScanRow(scan);
          });
          return;
        }

        scan.pdfDownloading = true;
        this.refreshScanRow(scan);

        const filename = `rapport_cyberscan_${scan.id}_${(scan.domaine || 'scan').replace(/[^\w.-]+/g, '_')}.pdf`;
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        scan.pdfDownloading = false;
        scan.rapportStatus = 'pret';
        scan.pdf_disponible = true;
        scan.has_rapport = true;
        this.showActionMessage('success', `Rapport PDF de ${scan.domaine} téléchargé avec succès.`);
        this.toastService.success(`Rapport PDF de ${scan.domaine} téléchargé avec succès.`);
        this.refreshScanRow(scan);
      },
      error: async (err) => {
        scan.pdfGenerating = false;
        scan.pdfDownloading = false;
        scan.rapportStatus = 'erreur';
        const msg = await this.blobErrorMessage(
          err,
          `Échec du téléchargement du rapport PDF pour ${scan.domaine}.`,
        );
        this.showActionMessage('error', msg);
        this.toastService.error(msg);
        this.refreshScanRow(scan);
      },
    });
  }

  /**
   * Envoie le rapport par email (API).
   * POST /api/scans/:id/rapport/email/
   * (L'envoi automatique post-scan reste géré côté backend via finalize_scan_report.)
   */
  envoyerRapportEmail(scan: any, event?: Event) {
    event?.stopPropagation();
    if (scan.emailSending) return;

    this.clearActionMessage();
    scan.emailSending = true;
    scan.emailStatus = 'envoi';
    this.refreshScanRow(scan);

    this.scannerService.sendRapportEmail(scan.id).subscribe({
      next: (res) => {
        scan.emailSending = false;
        scan.emailStatus = 'envoye';
        const recipients = (res?.recipients || []).join(', ');
        const emailMsg = recipients
          ? `Rapport de ${scan.domaine} envoyé à ${recipients}.`
          : `Rapport de ${scan.domaine} envoyé par email avec succès.`;
        this.showActionMessage('success', emailMsg);
        this.toastService.success(emailMsg);
        this.refreshScanRow(scan);
      },
      error: (err) => {
        scan.emailSending = false;
        scan.emailStatus = 'erreur';
        const msg = this.extractErrorMessage(
          err,
          `Échec de l'envoi du rapport par email pour ${scan.domaine}.`,
        );
        this.showActionMessage('error', msg);
        this.toastService.error(msg);
        this.refreshScanRow(scan);
      },
    });
  }

  exportPdf(scan: any, event?: Event) {
    event?.stopPropagation();
    this.exportService.downloadPdf(scan.id).subscribe({
      next: (blob) => {
        this.exportService.triggerDownload(blob, `rapport_${scan.id}_${scan.domaine || 'scan'}.pdf`);
        this.toastService.success(`Rapport PDF généré pour ${scan.domaine}`);
      },
      error: () => this.toastService.error(`Échec export PDF pour ${scan.domaine}`),
    });
  }

  exportExcel(scan: any, event?: Event) {
    event?.stopPropagation();
    this.exportService.downloadExcel(scan.id).subscribe({
      next: (blob) => {
        this.exportService.triggerDownload(blob, `rapport_${scan.id}_${scan.domaine || 'scan'}.xlsx`);
        this.toastService.success(`Rapport Excel généré pour ${scan.domaine}`);
      },
      error: () => this.toastService.error(`Échec export Excel pour ${scan.domaine}`),
    });
  }

  exportJson(scan: any, event?: Event) {
    event?.stopPropagation();
    this.exportService.downloadJson(scan.id).subscribe({
      next: (blob) => {
        this.exportService.triggerDownload(blob, `rapport_${scan.id}_${scan.domaine || 'scan'}.json`);
        this.toastService.success(`Rapport JSON généré pour ${scan.domaine}`);
      },
      error: () => this.toastService.error(`Échec export JSON pour ${scan.domaine}`),
    });
  }

  isScanBusy(scan: any): boolean {
    return !!(scan?.pdfGenerating || scan?.pdfDownloading || scan?.emailSending);
  }

  lancerRecherche() {
    this.currentPage = 1;
    this.loadScans(1);
  }

  onFilterChange() {
    this.currentPage = 1;
    this.loadScans(1);
  }

  onPageChange(event: PageEvent) {
    this.pageSize = event.pageSize;
    this.currentPage = event.pageIndex + 1;
    this.loadScans(this.currentPage);
  }

  viewScan(scan: any) {
    this.revokeQrCodeUrl();
    this.detailError = '';
    this.detailLoading = true;
    this.vulnsManuelles = [];
    this.selectedScan = this.buildDetailViewModel(this.mapScanUi({ ...scan }));
    this.chatbotContext.setScanContext(this.selectedScan);
    this.loadVulnsManuelles(scan.id);

    this.scannerService.getScan(scan.id).subscribe({
      next: (detail) => {
        const uiState = {
          pdfGenerating: this.selectedScan?.pdfGenerating ?? false,
          pdfDownloading: this.selectedScan?.pdfDownloading ?? false,
          emailSending: this.selectedScan?.emailSending ?? false,
        };
        this.selectedScan = this.buildDetailViewModel(this.mapScanUi({
          ...scan,
          ...detail,
          ...uiState,
          rapport_status: detail.report_status ?? scan.rapportStatus,
          email_status: detail.email_status ?? scan.emailStatus,
        }));
        this.chatbotContext.setScanContext(this.selectedScan);
        this.detailLoading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.detailError = this.extractErrorMessage(
          err,
          'Impossible de charger le d\u00e9tail complet du scan.',
        );
        this.detailLoading = false;
        this.cdr.detectChanges();
      },
    });
  }

  closeModal() {
    this.revokeQrCodeUrl();
    this.selectedScan = null;
    this.selectedProtocol = null;
    this.detailError = '';
    this.chatbotContext.clearScanContext();
  }
  deleteScan(scan: any, event: Event) {
    event.stopPropagation();
    this.http.delete(`${this.apiUrl}/scans/${scan.id}/`).subscribe({
      next: () => {
        this.scans = this.scans.filter((s) => s.id !== scan.id);
        this.dataSource.data = this.scans;
        if (this.selectedScan?.id === scan.id) this.closeModal();
        this.loadScans(this.currentPage);
      },
      error: () => alert('Erreur lors de la suppression'),
    });
  }

  loadVulnsManuelles(scanId: number) {
    this.http.get<any[]>(this.apiUrl + '/scans/' + scanId + '/vulnerabilites/').subscribe({
      next: (data) => {
        this.vulnsManuelles = data;
        if (this.selectedScan?.id === scanId) {
          this.selectedScan = this.buildDetailViewModel(this.selectedScan);
          this.cdr.detectChanges();
        }
      },
      error: () => {
        this.vulnsManuelles = [];
        if (this.selectedScan?.id === scanId) {
          this.selectedScan = this.buildDetailViewModel(this.selectedScan);
          this.cdr.detectChanges();
        }
      },
    });
  }
  openVulnForm() {
    this.showVulnForm = true;
  }

  onVulnFormClose() {
    this.showVulnForm = false;
  }

  onVulnAdded() {
    if (this.selectedScan) this.loadVulnsManuelles(this.selectedScan.id);
  }

  deleteVulnManuelle(id: number) {
    this.http.delete(`http://127.0.0.1:8000/api/vulnerabilites/${id}/`).subscribe({
      next: () => {
        this.vulnsManuelles = this.vulnsManuelles.filter((v) => v.id !== id);
      },
    });
  }

  private buildDetailViewModel(scan: any): any {
    const results = scan?.resultats_ssl ?? {};
    const findings = this.collectFindings(scan);
    const score = Number(scan?.score_risque_ia ?? 0);
    const securityScore = Math.max(0, 10 - score);
    const protocols = this.buildProtocolView(results.protocols ?? []);
    const technologies = results.whatweb?.technologies ?? scan?.whatweb?.technologies ?? [];
    const tools = this.buildToolResults(results);
    const timeline = this.buildTimeline(scan, results);
    const certificate = results.certificate ?? null;
    const certificateStatus = !certificate
      ? 'Non d\u00e9termin\u00e9'
      : certificate.expired === true
        ? 'expir\u00e9'
        : certificate.expired === false
          ? 'valide'
          : 'pr\u00e9sent';
    const riskLabel = this.riskLabel(score);
    const severityCounts = {
      critical: findings.filter((item: any) => item.severityKey === 'critical').length,
      high: findings.filter((item: any) => item.severityKey === 'high').length,
      medium: findings.filter((item: any) => item.severityKey === 'medium').length,
      low: findings.filter((item: any) => item.severityKey === 'low').length,
    };
    const ports = Array.isArray(results.ports) ? results.ports : [];
    const serviceCount = new Set(ports.map((port: any) => port?.service).filter(Boolean)).size;
    const toolCount = tools.filter((tool: any) => tool.statusKey === 'completed').length;
    const cveCount = findings.filter((item: any) => !!item.cve).length;
    const totalVulnerabilities = findings.length;
    const kpis = [
      { icon: '\u26a0', value: totalVulnerabilities, label: 'Vuln\u00e9rabilit\u00e9s', tone: 'neutral' },
      { icon: '\u25c6', value: severityCounts.critical, label: 'Critiques', tone: 'critical' },
      { icon: '\u25b2', value: severityCounts.high, label: '\u00c9lev\u00e9es', tone: 'high' },
      { icon: '\u25cf', value: severityCounts.medium, label: 'Moyennes', tone: 'medium' },
      { icon: '\u25bc', value: severityCounts.low, label: 'Faibles', tone: 'low' },
      { icon: 'CVE', value: cveCount, label: 'CVE d\u00e9tect\u00e9es', tone: 'cyan' },
      { icon: 'P', value: ports.length, label: 'Ports ouverts', tone: 'cyan' },
      { icon: 'S', value: serviceCount, label: 'Services d\u00e9tect\u00e9s', tone: 'cyan' },
      { icon: 'T', value: technologies.length, label: 'Technologies', tone: 'cyan' },
      { icon: 'O', value: toolCount, label: 'Outils ex\u00e9cut\u00e9s', tone: 'green' },
    ];
    const primaryFinding = [...findings].sort(
      (left: any, right: any) => (right.score ?? -1) - (left.score ?? -1),
    )[0] ?? null;
    const durationSeconds = Number(scan?.duration_seconds ?? results.scan_duration_seconds ?? 0);
    const domain = scan?.domaine ?? 'non renseigne';
    const pluralVerb = totalVulnerabilities > 1 ? 's ont' : ' a';
    const pluralSuffix = totalVulnerabilities > 1 ? 's' : '';

    return {
      ...scan,
      resultats_ssl: results,
      riskLabel,
      statut: riskLabel.toUpperCase(),
      riskClass: this.riskClass(score),
      securityScore: securityScore.toFixed(1),
      durationLabel: this.formatDuration(durationSeconds),
      certificateStatus,
      reportStatusLabel: this.getRapportStatusLabel(scan?.rapportStatus),
      emailStatusLabel: this.getEmailStatusLabel(scan?.emailStatus),
      protocolsUi: protocols,
      technologiesUi: technologies,
      toolsUi: tools,
      timelineUi: timeline,
      allFindings: findings,
      primaryFinding,
      kpis,
      httpsPort: ports.find((port: any) => Number(port?.port) === 443) ?? null,
      executiveSummary:
        "L'audit de s\u00e9curit\u00e9 du domaine " + domain +
        ' a \u00e9t\u00e9 r\u00e9alis\u00e9 le ' + this.formatDateTime(scan?.date_scan) + '. ' +
        "L'analyse attribue un niveau de risque " + riskLabel +
        ' avec un score IA de ' + score.toFixed(1) + '/10 et un score de s\u00e9curit\u00e9 de ' +
        securityScore.toFixed(1) + '/10. ' + totalVulnerabilities + ' vuln\u00e9rabilit\u00e9' +
        pluralVerb + ' \u00e9t\u00e9 d\u00e9tect\u00e9e' + pluralSuffix + '. Le certificat SSL est ' +
        certificateStatus + '. Les principales recommandations sont disponibles dans le rapport.',
    };
  }

  private collectFindings(scan: any): any[] {
    const results = scan?.resultats_ssl ?? {};
    const findings: any[] = [];
    const seen = new Set<string>();
    const add = (item: any) => {
      const key = String(item.cve ?? item.name ?? item.description ?? findings.length).toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      const score = item.score == null ? null : Number(item.score);
      findings.push({
        ...item,
        score: Number.isFinite(score) ? score : null,
        severityKey: this.severityKey(item.severity, score),
      });
    };

    for (const cve of scan?.cves ?? []) {
      add({
        name: cve.produit_concerne || cve.cve_id,
        cve: cve.cve_id,
        score: cve.cvss_score,
        severity: null,
        description: cve.description,
        impact: cve.description,
        solution: cve.recommandation_ia,
        priority: this.priorityLabel(cve.cvss_score),
      });
    }
    for (const cve of results.nvd_cves ?? []) {
      add({
        name: cve.produit_concerne || cve.cve_id || cve.id,
        cve: cve.cve_id || cve.id,
        score: cve.cvss_score ?? cve.cvssScore ?? cve.score,
        severity: cve.severity ?? cve.baseSeverity,
        description: cve.description,
        impact: cve.description,
        solution: cve.recommendation ?? cve.recommandation,
        priority: this.priorityLabel(cve.cvss_score ?? cve.score),
      });
    }
    for (const finding of results.zap_findings ?? []) {
      const mappedScore = finding.cvss_score ?? this.scoreFromSeverity(finding.risk);
      add({
        name: finding.name || 'Alerte OWASP ZAP',
        cve: finding.cve_id ?? null,
        score: mappedScore,
        severity: finding.risk,
        description: finding.description,
        impact: finding.other_info || finding.impact,
        solution: finding.solution,
        priority: this.priorityLabel(mappedScore),
      });
    }
    for (const finding of results.nuclei_findings ?? []) {
      const mappedScore = finding.cvss_score ?? this.scoreFromSeverity(finding.severity);
      add({
        name: finding.name || finding.template_id || 'Constat Nuclei',
        cve: String(finding.template_id ?? '').startsWith('CVE-') ? finding.template_id : null,
        score: mappedScore,
        severity: finding.severity,
        description: finding.description || finding.matched_at,
        impact: finding.description,
        solution: finding.remediation,
        priority: this.priorityLabel(mappedScore),
      });
    }
    for (const vulnerability of results.vulnerabilities ?? []) {
      add({
        name: String(vulnerability),
        cve: null,
        score: null,
        severity: null,
        description: 'Constat technique d\u00e9tect\u00e9 par les outils du scan.',
        impact: 'Impact \u00e0 confirmer selon le contexte de l\u2019actif.',
        solution: 'Consulter la fiche technique et le rapport pour la rem\u00e9diation.',
        priority: '\u00c0 qualifier',
      });
    }
    for (const manual of this.vulnsManuelles ?? []) {
      add({
        name: manual.nom,
        cve: null,
        score: manual.cvss_score,
        severity: manual.risk,
        description: manual.description,
        impact: manual.technical_business_risks,
        solution: manual.recommandation,
        priority: manual.priorite || this.priorityLabel(manual.cvss_score),
        manual: true,
        id: manual.id,
      });
    }
    return findings;
  }

  private buildToolResults(results: any): any[] {
    const executions = results.tool_executions ?? {};
    const ports = Array.isArray(results.ports) ? results.ports : [];
    const technologies = results.whatweb?.technologies ?? [];
    const definitions = [
      { key: 'sslscan', label: 'SSLScan', present: !!results.sslscan, count: (results.protocols?.length ?? 0) + (results.cipher_suites?.length ?? 0), error: results.sslscan_error },
      { key: 'nmap', label: 'Nmap', present: !!results.nmap, count: ports.length, error: results.nmap_error },
      { key: 'openssl', label: 'OpenSSL', present: !!results.openssl, count: results.certificate ? 1 : 0, error: results.openssl_error },
      { key: 'whatweb', label: 'WhatWeb', present: results.whatweb?.success === true || technologies.length > 0, count: technologies.length, error: results.whatweb?.error },
      { key: 'ssllabs', label: 'SSL Labs', present: results.ssllabs?.success === true || !!results.ssllabs?.grade, count: results.ssllabs?.grade && results.ssllabs.grade !== 'N/A' ? 1 : 0, error: results.ssllabs?.error },
      { key: 'nvd', label: 'NVD', present: results.nvd?.requested === true || (results.nvd_cves?.length ?? 0) > 0, count: results.nvd_cves?.length ?? results.nvd?.cves_count ?? 0, error: results.nvd?.success === false ? (results.nvd?.errors ?? []).join(', ') : null },
      { key: 'zap', label: 'OWASP ZAP', present: results.zap_success === true || !!results.zap_raw || (results.zap_findings?.length ?? 0) > 0, count: results.zap_findings?.length ?? 0, error: results.zap_error },
    ];
    return definitions.map((tool) => {
      const execution = executions[tool.key] ?? {};
      const wasMeasured = Object.keys(execution).length > 0;
      const statusKey = tool.error || execution.success === false
        ? 'failed'
        : tool.present || wasMeasured
          ? 'completed'
          : 'not-run';
      return {
        ...tool,
        statusKey,
        statusLabel: statusKey === 'completed' ? 'Termin\u00e9' : statusKey === 'failed' ? '\u00c9chec' : 'Non ex\u00e9cut\u00e9',
        completedAt: execution.completed_at ?? null,
        durationLabel: this.formatDuration(execution.duration_seconds),
      };
    });
  }

  private buildProtocolView(protocols: any[]): any[] {
    return (protocols ?? []).map((protocol: any) => {
      const name = String(protocol?.name ?? protocol);
      const rawStatus = String(protocol?.status ?? '').toLowerCase();
      const legacy = name === 'TLSv1.0' || name === 'TLSv1.1';
      const disabled = ['disabled', 'rejected', 'not supported'].includes(rawStatus);
      let statusKey = 'acceptable';
      let statusLabel = 'Acceptable';
      if (legacy && !disabled) {
        statusKey = 'obsolete';
        statusLabel = 'Obsol\u00e8te';
      } else if (name === 'TLSv1.3' && !disabled) {
        statusKey = 'recommended';
        statusLabel = 'Recommand\u00e9';
      } else if (disabled && legacy) {
        statusKey = 'recommended';
        statusLabel = 'Recommand\u00e9';
      }
      return { ...protocol, name, statusKey, statusLabel };
    });
  }

  private buildTimeline(scan: any, results: any): any[] {
    const items = [...(scan?.timeline ?? [])].map((item: any) => ({
      label: item.label,
      timestamp: item.timestamp,
      type: item.type,
    }));
    const executions = results.tool_executions ?? {};
    for (const [key, execution] of Object.entries<any>(executions)) {
      if (execution?.completed_at) {
        items.push({
          label: key + ' termin\u00e9',
          timestamp: execution.completed_at,
          type: 'tool.' + key,
        });
      }
    }
    if (!items.length && scan?.started_at) {
      items.push({ label: 'Scan lanc\u00e9', timestamp: scan.started_at, type: 'scan.running' });
    }
    if (scan?.completed_at && !items.some((item: any) => item.type === 'scan.completed')) {
      items.push({ label: 'Scan termin\u00e9', timestamp: scan.completed_at, type: 'scan.completed' });
    }
    return items.sort(
      (left: any, right: any) =>
        new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime(),
    );
  }

  private riskLabel(score: number): string {
    if (score >= 9) return 'Critique';
    if (score >= 7) return '\u00c9lev\u00e9';
    if (score >= 4) return 'Moyen';
    return 'Faible';
  }

  private riskClass(score: number): string {
    if (score >= 9) return 'risk-critical';
    if (score >= 7) return 'risk-high';
    if (score >= 4) return 'risk-medium';
    return 'risk-low';
  }

  private severityKey(severity: any, score: number | null): string {
    const value = String(severity ?? '').toLowerCase();
    if (value.includes('critical') || value.includes('critique') || (score != null && score >= 9)) return 'critical';
    if (value.includes('high') || value.includes('\u00e9lev') || (score != null && score >= 7)) return 'high';
    if (value.includes('medium') || value.includes('moyen') || (score != null && score >= 4)) return 'medium';
    if (value.includes('low') || value.includes('faible') || score != null) return 'low';
    return 'unknown';
  }

  private scoreFromSeverity(severity: any): number | null {
    const value = String(severity ?? '').toLowerCase();
    if (value.includes('critical') || value.includes('critique')) return 9.5;
    if (value.includes('high') || value.includes('\u00e9lev')) return 7.5;
    if (value.includes('medium') || value.includes('moyen')) return 5;
    if (value.includes('low') || value.includes('faible')) return 2;
    return null;
  }

  private priorityLabel(score: any): string {
    const value = Number(score);
    if (!Number.isFinite(value)) return '\u00c0 qualifier';
    if (value >= 9) return 'P1 - Imm\u00e9diate';
    if (value >= 7) return 'P1 - Prioritaire';
    if (value >= 4) return 'P2 - Planifi\u00e9e';
    return 'P3 - Surveillance';
  }

  private formatDuration(seconds: any): string {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) return 'Non mesur\u00e9e';
    const rounded = Math.round(value);
    const minutes = Math.floor(rounded / 60);
    const remaining = rounded % 60;
    return minutes
      ? minutes + ' min ' + String(remaining).padStart(2, '0') + ' s'
      : remaining + ' s';
  }

  private formatDateTime(value: any): string {
    if (!value) return 'date non renseign\u00e9e';
    return new Intl.DateTimeFormat('fr-FR', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(value));
  }

  consulterRapport(scan: any, event?: Event) {
    event?.stopPropagation();
    this.scannerService.downloadRapportPdf(scan.id).subscribe({
      next: (blob) => {
        const url = URL.createObjectURL(blob);
        window.open(url, '_blank', 'noopener,noreferrer');
        setTimeout(() => URL.revokeObjectURL(url), 60000);
      },
      error: (err) => this.toastService.error(
        this.extractErrorMessage(err, 'Impossible d\u2019ouvrir le rapport.'),
      ),
    });
  }

  imprimerRapport(scan: any, event?: Event) {
    event?.stopPropagation();
    this.scannerService.downloadRapportPdf(scan.id).subscribe({
      next: (blob) => {
        const url = URL.createObjectURL(blob);
        const printWindow = window.open(url, '_blank');
        if (printWindow) {
          printWindow.addEventListener('load', () => printWindow.print(), { once: true });
        }
        setTimeout(() => URL.revokeObjectURL(url), 60000);
      },
      error: () => this.toastService.error('Impossible d\u2019imprimer le rapport.'),
    });
  }

  genererQrCode(scan: any, event?: Event) {
    event?.stopPropagation();
    if (this.qrLoading) return;
    this.qrLoading = true;
    this.revokeQrCodeUrl();
    this.scannerService.getReportQr(scan.id).subscribe({
      next: (blob) => {
        this.qrCodeUrl = URL.createObjectURL(blob);
        this.qrLoading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.qrLoading = false;
        this.toastService.error('Impossible de g\u00e9n\u00e9rer le QR Code.');
        this.cdr.detectChanges();
      },
    });
  }

  relancerScan(scan: any, event?: Event) {
    event?.stopPropagation();
    if (this.relaunching) return;
    this.relaunching = true;
    this.scannerService.demarrerScan(scan.domaine, {}).subscribe({
      next: () => {
        this.relaunching = false;
        this.toastService.success('Nouveau scan de ' + scan.domaine + ' mis en file.');
        this.closeModal();
        this.loadScans(1);
      },
      error: (err) => {
        this.relaunching = false;
        this.toastService.error(this.extractErrorMessage(err, 'Impossible de relancer le scan.'));
        this.cdr.detectChanges();
      },
    });
  }

  voirToutesLesVulnerabilites() {
    document.getElementById('all-vulnerabilities')?.scrollIntoView({
      behavior: 'smooth',
      block: 'start',
    });
  }

  private revokeQrCodeUrl() {
    if (this.qrCodeUrl) {
      URL.revokeObjectURL(this.qrCodeUrl);
      this.qrCodeUrl = null;
    }
  }
  showProtocolDetail(protocol: any) {
    const info: any = {
      'TLSv1.0': {
        titre: 'TLS 1.0 — VULNÉRABLE',
        description: 'Vulnérable aux attaques POODLE et BEAST.',
        risque: 'ÉLEVÉ',
        solution: 'Désactiver TLS 1.0 et migrer vers TLS 1.2+.',
      },
      'TLSv1.1': {
        titre: 'TLS 1.1 — OBSOLÈTE',
        description: 'Déprécié par RFC 8996 en 2021.',
        risque: 'MOYEN',
        solution: 'Désactiver TLS 1.1.',
      },
      'TLSv1.2': {
        titre: 'TLS 1.2 — SÉCURISÉ',
        description: 'Protocole sécurisé recommandé.',
        risque: 'FAIBLE',
        solution: 'Aucune action requise.',
      },
      'TLSv1.3': {
        titre: 'TLS 1.3 — OPTIMAL',
        description: 'Meilleure sécurité et performance.',
        risque: 'AUCUN',
        solution: 'Configuration optimale.',
      },
    };

    const baseInfo = info[protocol.name] ?? {
      titre: protocol.name,
      description: 'Protocole détecté.',
      risque: protocol.status,
      solution: 'Consulter la documentation.',
    };

    let aiSolution = '';

    if (this.selectedScan && this.selectedScan.cves) {
      const matchingCve = this.selectedScan.cves.find(
        (c: any) =>
          (protocol.name === 'TLSv1.0' && c.cve_id === 'CVE-2014-3566') ||
          (protocol.name === 'WEAK_CIPHER' && c.cve_id === 'CVE-2016-2183'),
      );

      if (matchingCve && matchingCve.recommandation_ia) {
        aiSolution = matchingCve.recommandation_ia;
      }
    }

    this.selectedProtocol = {
      ...baseInfo,
      recommandation_ia: aiSolution || baseInfo.solution,
    };
  }

  closeProtocolDetail() {
    this.selectedProtocol = null;
  }

  startMatrix() {
    setTimeout(() => {
      const canvas = document.getElementById('hist-matrix') as HTMLCanvasElement;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const cols = Math.floor(canvas.width / 14);
      const drops = Array(cols).fill(1);
      this.matrixInterval = setInterval(() => {
        ctx.fillStyle = 'rgba(0,0,0,0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00FF41';
        ctx.font = '13px monospace';
        drops.forEach((y, i) => {
          const ch = String.fromCharCode(0x30a0 + Math.random() * 96);
          ctx.fillText(ch, i * 14, y * 14);
          if (y * 14 > canvas.height && Math.random() > 0.975) drops[i] = 0;
          drops[i]++;
        });
      }, 50);
    }, 100);
  }
}

export { Historique };
