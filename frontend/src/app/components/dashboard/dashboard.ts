import { ChangeDetectorRef, Component, OnDestroy, OnInit, ViewEncapsulation } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { ScannerService } from '../../services/scanner.service';
import { DataSyncService } from '../../services/data-sync.service';
import { finalize, Subject, takeUntil } from 'rxjs';

@Component({
  selector: 'app-dashboard',
  imports: [FormsModule, CommonModule, RouterLink],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
  standalone: true,
  encapsulation: ViewEncapsulation.None,
})
export class Dashboard implements OnInit, OnDestroy {
  critiques = 0;
  moyennes = 0;
  totalScans = 0;
  totalCve = 0;
  loadingStats = true;
  recentScans: any[] = [];
  userRole: string = '';

  private matrixInterval: any;
  private readonly destroy$ = new Subject<void>();

  constructor(
    private scannerService: ScannerService,
    private authService: AuthService,
    private dataSync: DataSyncService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit() {
    this.userRole = this.authService.getUserRole();
    this.loadDashboardData();
    this.dataSync.dashboardRefresh$
      .pipe(takeUntil(this.destroy$))
      .subscribe(() => this.loadDashboardData());
    this.startMatrix();
  }

  loadDashboardData() {
    this.loadingStats = true;
    this.scannerService.getDashboardStats().pipe(
      finalize(() => {
        this.loadingStats = false;
        this.cdr.detectChanges();
      }),
    ).subscribe({
      next: (data) => {
        console.log('Data reçue du Backend Django:', data);

        this.totalScans = data.total_scans ?? 0;
        this.critiques = data.critical_count ?? 0;
        this.moyennes = data.medium_count ?? 0;
        this.totalCve = data.total_recommandations ?? data.total_cve ?? 0;
        this.recentScans = data.recent_scans ?? [];

        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Erreur lors du chargement des statistiques CYBERSCAN', err);
        this.resetStats();
        this.cdr.detectChanges();
      },
    });
  }

  ngOnDestroy() {
    this.destroy$.next();
    this.destroy$.complete();
    if (this.matrixInterval) clearInterval(this.matrixInterval);
  }

  private resetStats() {
    this.critiques = 0;
    this.moyennes = 0;
    this.totalScans = 0;
    this.totalCve = 0;
    this.recentScans = [];
  }

  private startMatrix() {
    setTimeout(() => {
      const canvas = document.getElementById('matrix-canvas') as HTMLCanvasElement | null;
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
