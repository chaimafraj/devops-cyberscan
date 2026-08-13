import { Component, OnInit, OnDestroy, ViewEncapsulation, ChangeDetectorRef } from '@angular/core';
import { Subscription, switchMap, timer } from 'rxjs';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { ScannerService } from '../../services/scanner.service';
import { ToastService } from '../../services/toast.service';
import { NotificationService } from '../../services/notification.service';
import { NucleiFinding, ScanResponse, SiteReport, ZapFinding } from '../../models/scan.model';

type ScanUiStatus = 'IDLE' | 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

@Component({
  selector: 'app-scanner',
  imports: [FormsModule, CommonModule, HttpClientModule],
  templateUrl: './scanner.html',
  styleUrl: './scanner.scss',
  standalone: true,
  encapsulation: ViewEncapsulation.None,
})
export class Scanner implements OnInit, OnDestroy {
  targetUrl = '';
  port = '443';
  scanning = false;
  cancelling = false;
  cancelMessage = '';
  activeScanId: number | null = null;
  scanResult: SiteReport | null = null;
  zapFindings: ZapFinding[] = [];
  zapRequested = false;
  nucleiFindings: NucleiFinding[] = [];
  nucleiRequested = false;
  errorMsg = '';
  targetError = '';
  scanStatus: ScanUiStatus = 'IDLE';
  private scanPolling?: Subscription;
  private matrixInterval: any;

  // Accepte : domaine (google.com), IPv4 (1.2.3.4), ou host:port (esprit.tn:8443)
  private readonly TARGET_REGEX =
    /^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?$/;

  options = [
    { id: 'sslscan', label: 'SSLSCAN', checked: true },
    { id: 'nmap', label: 'NMAP SSL', checked: true },
    { id: 'openssl', label: 'OPENSSL', checked: true },
    { id: 'ssllabs', label: 'SSL LABS API', checked: false },
    { id: 'whatweb', label: 'WHATWEB', checked: false },
    { id: 'zap', label: 'OWASP ZAP Baseline', checked: false },
    { id: 'nuclei', label: 'NUCLEI', checked: false },
    { id: 'nvd', label: 'NVD (National Vulnerability Database)', checked: true },
  ];

  constructor(
    private scannerService: ScannerService,
    private toastService: ToastService,
    private notifService: NotificationService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit() {
    this.startMatrix();
    this.resumeLatestScan();
  }

  ngOnDestroy() {
    this.scanPolling?.unsubscribe();
    if (this.matrixInterval) clearInterval(this.matrixInterval);
  }

  // Valide le champ "Domaine cible" (domaine, IP, ou host:port). Renvoie true si vide/valide.
  validateTarget(): boolean {
    const value = (this.targetUrl || '').trim();
    if (!value) {
      this.targetError = '';
      return false;
    }
    if (!this.TARGET_REGEX.test(value)) {
      this.targetError = 'Format invalide. Exemples : google.com, 193.95.99.197, ou esprit.tn:8443';
      return false;
    }
    this.targetError = '';
    return true;
  }

  // Construit la cible envoyée au backend : "host" seul, ou "host:port" si le port != 443.
  // Le port saisi dans le champ domaine (host:port) prime sur le champ PORT séparé.
  private buildTarget(): string {
    const value = (this.targetUrl || '').trim();
    const [host, portInUrl] = value.split(':');
    const port = (portInUrl || this.port || '443').trim();
    return port && port !== '443' ? `${host}:${port}` : host;
  }

  private resumeLatestScan(): void {
    this.scannerService.getRecentScans().subscribe({
      next: (response) => {
        if (this.scanning) return;
        const scans = Array.isArray(response?.results) ? response.results : [];
        const activeScan =
          scans.find((scan) => String(scan?.status).toUpperCase() === 'RUNNING') ??
          scans.find((scan) => String(scan?.status).toUpperCase() === 'PENDING');

        if (activeScan?.id) {
          this.targetUrl = activeScan.domaine || this.targetUrl;
          this.scanning = true;
          this.activeScanId = Number(activeScan.id);
          this.scanStatus = String(activeScan.status).toUpperCase() as ScanUiStatus;
          this.pollScan(activeScan.id, activeScan.domaine || this.targetUrl);
          this.cdr.detectChanges();
          return;
        }


      },
      error: () => {
        // Le lancement manuel reste disponible si l'historique est momentanément inaccessible.
      },
    });
  }
  nouveauScan(): void {
    this.scanResult = null;
    this.zapFindings = [];
    this.nucleiFindings = [];
    this.scanStatus = 'IDLE';
    this.errorMsg = '';
    this.cancelMessage = '';
    this.cdr.detectChanges();
  }
  lancerScan() {
    if (!this.validateTarget()) return;

    const target = this.buildTarget();
    this.scanPolling?.unsubscribe();
    this.activeScanId = null;
    this.cancelling = false;
    this.cancelMessage = '';
    this.scanning = true;
    this.scanStatus = 'PENDING';
    this.scanResult = null;
    this.zapFindings = [];
    this.nucleiFindings = [];
    this.errorMsg = '';

    const options = this.options.reduce(
      (acc, opt) => {
        acc[opt.id] = opt.checked;
        return acc;
      },
      {} as Record<string, boolean>,
    );

    this.zapRequested = options['zap'] ?? false;
    this.nucleiRequested = options['nuclei'] ?? false;

    this.scannerService.demarrerScan(target, options).subscribe({
      next: (result: ScanResponse) => {
        const queuedScan = result?.scans?.[0];
        if (queuedScan?.scan_id) {
          this.activeScanId = Number(queuedScan.scan_id);
          this.scanStatus = queuedScan.status || 'PENDING';
          this.toastService.success(`Scan ajouté à la file d’attente pour ${target}`);
          this.pollScan(queuedScan.scan_id, target);
          this.cdr.detectChanges();
          return;
        }

        this.displayCompletedScan(result, target);
      },
      error: (err) => {
        this.stopWithError(
          err?.error?.error || 'Erreur lors du lancement. Vérifiez Redis et le worker Celery.',
        );
      },
    });
  }

  annulerScan(): void {
    if (!this.activeScanId || !this.scanning || this.cancelling) return;

    const scanId = this.activeScanId;
    this.cancelling = true;
    this.scannerService.cancelScan(scanId).subscribe({
      next: () => {
        this.scanPolling?.unsubscribe();
        this.activeScanId = null;
        this.scanning = false;
        this.cancelling = false;
        this.scanStatus = 'CANCELLED';
        this.cancelMessage = 'Le scan a été annulé avec succès.';
        this.toastService.info(this.cancelMessage);
        this.notifService.refreshNotifications();
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.cancelling = false;
        const error = err?.error?.error;
        const message = typeof error === 'string' ? error : error?.message;
        this.toastService.error(message || 'Impossible d’annuler ce scan.');
        this.cdr.detectChanges();
      },
    });
  }
  private pollScan(scanId: number, target: string): void {
    this.scanPolling = timer(0, 3000)
      .pipe(switchMap(() => this.scannerService.getScan(scanId)))
      .subscribe({
        next: (scan) => {
          const status = String(scan?.status || 'PENDING').toUpperCase();
          this.scanStatus = status as ScanUiStatus;


          if (status === 'COMPLETED') {
            this.scanPolling?.unsubscribe();
            this.displayCompletedScan(scan, target);
          } else if (status === 'FAILED') {
            this.scanPolling?.unsubscribe();
            this.stopWithError(scan?.error_message || `Le scan de ${target} a échoué.`);
          } else if (status === 'CANCELLED') {
            this.scanPolling?.unsubscribe();
            this.activeScanId = null;
            this.scanning = false;
            this.cancelling = false;
            this.cancelMessage = 'Le scan a été annulé.';
            this.notifService.refreshNotifications();
            this.cdr.detectChanges();
          } else {
            this.cdr.detectChanges();
          }
        },
        error: (err) => {
          this.scanPolling?.unsubscribe();
          this.stopWithError(
            err?.error?.error || 'Impossible de suivre le statut du scan.',
          );
        },
      });
  }

  private displayCompletedScan(result: any, target: string, notify = true): void {
    this.activeScanId = null;
    this.cancelling = false;
    this.scanning = false;
    this.scanStatus = 'COMPLETED';

    if (result?.resultats_ssl && typeof result.resultats_ssl === 'object') {
      this.scanResult = {
        ...result.resultats_ssl,
        id: result.id,
        domaine: result.domaine || target,
        score_risque_ia: result.score_risque_ia,
        cves: result.cves || result.resultats_ssl.cves || [],
      } as SiteReport;
    } else if (result?.rapport?.length > 0) {
      this.scanResult = result.rapport[0];
    } else {
      this.scanResult = result as SiteReport;
    }

    this.zapFindings = this.extraireZapFindings(result, this.scanResult);
    this.nucleiFindings = this.extraireNucleiFindings(result, this.scanResult);
    if (notify) {
      this.toastService.success(`Scan terminé pour ${target}`);
      this.notifService.fetchUnreadCount();

      const score = this.scanResult?.score_risque_ia ?? (this.scanResult as any)?.score;
      if (score != null && Number(score) >= 7) {
        this.toastService.warning(`Nouvelle CVE critique détectée sur ${target}`);
      }
    }
    this.cdr.detectChanges();
  }

  private stopWithError(message: string): void {
    this.activeScanId = null;
    this.cancelling = false;
    this.scanning = false;
    this.scanStatus = 'FAILED';
    this.errorMsg = message;
    this.toastService.error(message);
    this.cdr.detectChanges();
  }

  // Cherche zap_findings dans la réponse racine puis dans le rapport site
  private extraireZapFindings(root: ScanResponse, site: SiteReport | null): ZapFinding[] {
    const findings = root?.zap_findings ?? site?.zap_findings ?? [];
    return Array.isArray(findings) ? findings : [];
  }
  private extraireNucleiFindings(root: ScanResponse, site: SiteReport | null): NucleiFinding[] {
    const findings = root?.['nuclei_findings'] ?? site?.nuclei_findings ?? [];
    return Array.isArray(findings) ? findings : [];
  }
  // Normalise le niveau de risque pour le style CSS (high / medium / low / info)
  riskClass(risk: string): string {
    const r = (risk || '').toLowerCase();
    if (r.includes('high')) return 'high';
    if (r.includes('medium')) return 'medium';
    if (r.includes('low')) return 'low';
    return 'info';
  }
  startMatrix() {
    setTimeout(() => {
      const canvas = document.getElementById('scanner-matrix') as HTMLCanvasElement;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const cols = Math.floor(canvas.width / 14);
      const drops = Array(cols).fill(1);
      this.matrixInterval = setInterval(() => {
        const styles = getComputedStyle(document.body);
        ctx.fillStyle = styles.getPropertyValue('--matrix-fade').trim();
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = styles.getPropertyValue('--matrix-glyph').trim();
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
