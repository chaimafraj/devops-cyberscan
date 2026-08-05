import { Injectable, signal } from '@angular/core';
import { Subject } from 'rxjs';
import { SiteReport } from '../models/scan.model';

/**
 * Bus d'invalidation applicatif. Il ne stocke pas les réponses HTTP : chaque écran
 * actif recharge uniquement la ressource concernée après une mutation confirmée.
 */
@Injectable({ providedIn: 'root' })
export class DataSyncService {
  private readonly dashboardRefreshSubject = new Subject<void>();
  private readonly historyRefreshSubject = new Subject<void>();
  private readonly alertsRefreshSubject = new Subject<void>();
  private readonly notificationsRefreshSubject = new Subject<void>();
  private readonly chatbotScanSubject = new Subject<SiteReport>();

  readonly dashboardRefresh$ = this.dashboardRefreshSubject.asObservable();
  readonly historyRefresh$ = this.historyRefreshSubject.asObservable();
  readonly alertsRefresh$ = this.alertsRefreshSubject.asObservable();
  readonly notificationsRefresh$ = this.notificationsRefreshSubject.asObservable();
  readonly chatbotScan$ = this.chatbotScanSubject.asObservable();

  readonly lastCompletedScan = signal<SiteReport | null>(null);
  readonly scanRevision = signal(0);

  scanCompleted(scan: SiteReport): void {
    this.lastCompletedScan.set(scan);
    this.scanRevision.update((revision) => revision + 1);
    this.dashboardRefreshSubject.next();
    this.historyRefreshSubject.next();
    this.alertsRefreshSubject.next();
    this.notificationsRefreshSubject.next();
    this.chatbotScanSubject.next(scan);
  }

  scanDeleted(): void {
    this.dashboardRefreshSubject.next();
    this.historyRefreshSubject.next();
    this.alertsRefreshSubject.next();
    this.notificationsRefreshSubject.next();
  }

  vulnerabilityChanged(): void {
    this.dashboardRefreshSubject.next();
    this.historyRefreshSubject.next();
    this.alertsRefreshSubject.next();
  }

  notificationsChanged(): void {
    this.notificationsRefreshSubject.next();
  }
}
