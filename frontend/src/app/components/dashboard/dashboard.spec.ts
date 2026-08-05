import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Subject } from 'rxjs';
import { vi } from 'vitest';

import { Dashboard } from './dashboard';
import { ScannerService } from '../../services/scanner.service';
import { AuthService } from '../../services/auth.service';
import { DataSyncService } from '../../services/data-sync.service';

describe('Dashboard', () => {
  let component: Dashboard;
  let fixture: ComponentFixture<Dashboard>;
  let response$: Subject<any>;
  let refresh$: Subject<void>;
  let scannerService: { getDashboardStats: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    response$ = new Subject<any>();
    refresh$ = new Subject<void>();
    scannerService = { getDashboardStats: vi.fn(() => response$) };

    await TestBed.configureTestingModule({
      imports: [Dashboard],
      providers: [
        provideRouter([]),
        { provide: ScannerService, useValue: scannerService },
        { provide: AuthService, useValue: { getUserRole: () => 'user' } },
        { provide: DataSyncService, useValue: { dashboardRefresh$: refresh$.asObservable() } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(Dashboard);
    component = fixture.componentInstance;
  });

  it('shows loading placeholders and loads exact counters on the first response', () => {
    fixture.detectChanges();

    expect(scannerService.getDashboardStats).toHaveBeenCalledTimes(1);
    expect(component.loadingStats).toBe(true);
    expect(fixture.nativeElement.querySelectorAll('.stat-skeleton').length).toBe(4);
    expect(fixture.nativeElement.querySelector('.stats-grid').textContent).not.toContain('0');

    response$.next({
      total_scans: 10,
      critical_count: 9,
      medium_count: 0,
      total_recommandations: 14,
      recent_scans: [{ domaine: 'esprit.tn', score_risque_ia: 8 }],
    });
    response$.complete();
    fixture.detectChanges();

    expect(component.loadingStats).toBe(false);
    expect(component.critiques).toBe(9);
    expect(component.moyennes).toBe(0);
    expect(component.totalScans).toBe(10);
    expect(component.totalCve).toBe(14);
    expect(component.recentScans[0].domaine).toBe('esprit.tn');
    expect(fixture.nativeElement.querySelectorAll('.stat-skeleton').length).toBe(0);
  });

  it('reloads the dashboard after an application data invalidation', () => {
    fixture.detectChanges();
    refresh$.next();
    expect(scannerService.getDashboardStats).toHaveBeenCalledTimes(2);
  });
});
