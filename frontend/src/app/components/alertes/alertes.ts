import {
  ChangeDetectorRef,
  Component,
  HostListener,
  OnDestroy,
  OnInit,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';

interface AlerteDetailField {
  label: string;
  value: string;
  url?: string;
}

interface AlerteDetails {
  source_label: string;
  identifier: string;
  fields: AlerteDetailField[];
  recommendation: string;
}

interface AlerteItem {
  scan_id: number;
  domain: string;
  icon: string;
  titre: string;
  message: string;
  date: string | null;
  niveau: string;
  type: 'danger' | 'warn' | 'ok';
  source: string;
  source_id: string;
  details?: AlerteDetails;
}

interface AlerteStats {
  critiques: number;
  moyennes: number;
  faibles: number;
  total: number;
}

interface AlertesResponse {
  alertes?: AlerteItem[];
  stats?: AlerteStats;
}

const EMPTY_STATS: AlerteStats = {
  critiques: 0,
  moyennes: 0,
  faibles: 0,
  total: 0,
};

@Component({
  selector: 'app-alertes',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './alertes.html',
  styleUrl: './alertes.scss',
})
export class Alertes implements OnInit, OnDestroy {
  private matrixInterval?: ReturnType<typeof setInterval>;
  private matrixTimeout?: ReturnType<typeof setTimeout>;
  private readonly apiUrl = `${environment.API_BASE_URL}/alertes/`;

  alertes: AlerteItem[] = [];
  stats: AlerteStats = { ...EMPTY_STATS };
  selectedAlerte: AlerteItem | null = null;
  loading = true;
  loadError = false;

  constructor(
    private readonly http: HttpClient,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.startMatrix();
    this.loadAlertes();
  }

  ngOnDestroy(): void {
    if (this.matrixTimeout) clearTimeout(this.matrixTimeout);
    if (this.matrixInterval) clearInterval(this.matrixInterval);
  }

  loadAlertes(): void {
    this.loading = true;
    this.loadError = false;
    this.http.get<AlertesResponse>(this.apiUrl).subscribe({
      next: (data) => {
        this.alertes = data.alertes || [];
        this.stats = data.stats || { ...EMPTY_STATS };
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Erreur chargement alertes:', err);
        this.loadError = true;
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  openDetails(alerte: AlerteItem): void {
    this.selectedAlerte = alerte;
  }

  closeDetails(): void {
    this.selectedAlerte = null;
  }

  @HostListener('document:keydown.escape')
  closeDetailsWithEscape(): void {
    if (this.selectedAlerte) this.closeDetails();
  }

  private startMatrix(): void {
    this.matrixTimeout = setTimeout(() => {
      const canvas = document.getElementById('alertes-matrix') as HTMLCanvasElement | null;
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
