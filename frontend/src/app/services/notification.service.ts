import { environment } from '../../environments/environment';
import { Injectable, OnDestroy } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import {
  BehaviorSubject,
  Observable,
  Subscription,
  distinctUntilChanged,
  interval,
  of,
} from 'rxjs';
import { catchError, map, switchMap, tap } from 'rxjs/operators';
import { ToastService } from './toast.service';

export interface Notification {
  id: number;
  titre: string;
  message: string;
  niveau: 'alert' | 'success' | 'info' | 'warning';
  date: string;
  lu: boolean;
}

@Injectable({ providedIn: 'root' })
export class NotificationService implements OnDestroy {
  private readonly apiUrl = environment.API_BASE_URL;
  private readonly unreadCountSubject = new BehaviorSubject(0);
  private readonly notificationsSubject = new BehaviorSubject<Notification[]>([]);
  readonly unreadCount = this.unreadCountSubject.asObservable().pipe(distinctUntilChanged());
  readonly notifications$ = this.notificationsSubject.asObservable();

  private pollSub?: Subscription;
  private lastKnownCount = 0;

  constructor(
    private readonly http: HttpClient,
    private readonly toastService: ToastService,
  ) {}

  startPolling(intervalMs = 15_000): void {
    if (this.pollSub && !this.pollSub.closed) return;
    this.fetchUnreadCount(false);
    this.pollSub = interval(intervalMs)
      .pipe(
        switchMap(() => this.requestUnreadCount().pipe(catchError(() => of(this.lastKnownCount)))),
      )
      .subscribe((count) => this.handleCountUpdate(count, true));
  }

  stopPolling(): void {
    this.pollSub?.unsubscribe();
    this.pollSub = undefined;
  }

  fetchUnreadCount(notifyOnIncrease = false): void {
    this.requestUnreadCount()
      .pipe(catchError(() => of(this.lastKnownCount)))
      .subscribe((count) => this.handleCountUpdate(count, notifyOnIncrease));
  }

  getNotifications(): Observable<Notification[]> {
    return this.http.get<unknown>(`${this.apiUrl}/notifications/`).pipe(
      map((data: any) =>
        (Array.isArray(data) ? data : (data?.notifications ?? data?.results ?? [])).map((item: any) =>
          this.normalize(item),
        ),
      ),
      tap((list) => {
        this.notificationsSubject.next(list);
        this.handleCountUpdate(list.filter((notification) => !notification.lu).length, false);
      }),
    );
  }

  refreshNotifications(): void {
    this.getNotifications()
      .pipe(catchError(() => of(this.notificationsSubject.value)))
      .subscribe();
  }

  markAsRead(id: number): Observable<unknown> {
    return this.http.patch(`${this.apiUrl}/notifications/${id}/read/`, {}).pipe(
      tap(() => {
        const current = this.notificationsSubject.value;
        const wasUnread = current.some(
          (notification) => notification.id === id && !notification.lu,
        );
        this.notificationsSubject.next(
          current.map((notification) =>
            notification.id === id ? { ...notification, lu: true } : notification,
          ),
        );
        if (wasUnread) this.handleCountUpdate(Math.max(0, this.lastKnownCount - 1), false);
      }),
    );
  }

  markAllAsRead(): Observable<unknown> {
    return this.http.patch(`${this.apiUrl}/notifications/read-all/`, {}).pipe(
      tap(() => {
        this.notificationsSubject.next(
          this.notificationsSubject.value.map((notification) => ({ ...notification, lu: true })),
        );
        this.handleCountUpdate(0, false);
      }),
    );
  }

  deleteNotification(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/notifications/${id}/`).pipe(
      tap(() => {
        const removed = this.notificationsSubject.value.find(
          (notification) => notification.id === id,
        );
        this.notificationsSubject.next(
          this.notificationsSubject.value.filter((notification) => notification.id !== id),
        );
        if (removed && !removed.lu)
          this.handleCountUpdate(Math.max(0, this.lastKnownCount - 1), false);
      }),
    );
  }

  ngOnDestroy(): void {
    this.stopPolling();
  }

  private requestUnreadCount(): Observable<number> {
    return this.http
      .get<{ unread_count?: number; count?: number }>(`${this.apiUrl}/notifications/unread-count/`)
      .pipe(
        map((response) =>
          Math.max(0, Number(response?.unread_count ?? response?.count) || 0),
        ),
      );
  }

  private handleCountUpdate(count: number, notifyOnIncrease: boolean): void {
    const normalized = Math.max(0, Number(count) || 0);
    const previous = this.lastKnownCount;
    this.lastKnownCount = normalized;
    this.unreadCountSubject.next(normalized);
    if (notifyOnIncrease && normalized > previous) {
      this.getNotifications()
        .pipe(catchError(() => of([])))
        .subscribe((list) => {
          list
            .filter((notification) => !notification.lu)
            .slice(0, normalized - previous)
            .forEach((notification) => this.toastForNotification(notification));
        });
    }
  }

  private normalize(item: any): Notification {
    return {
      id: Number(item.id),
      titre: item.titre ?? item.title ?? '',
      message: item.message ?? item.body ?? '',
      niveau: this.normalizeLevel(item.niveau ?? item.level ?? item.severity ?? item.type),
      date: item.date ?? item.created_at ?? item.date_creation ?? item.timestamp ?? '',
      lu: !!(item.lu ?? item.read ?? item.is_read),
    };
  }

  private normalizeLevel(raw: string): Notification['niveau'] {
    const value = (raw || '').toLowerCase();
    if (['alert', 'critical', 'critique', 'danger', 'high'].includes(value)) return 'alert';
    if (['success', 'successful', 'ok', 'resolved'].includes(value)) return 'success';
    if (['warning', 'warn', 'moyen', 'medium'].includes(value)) return 'warning';
    return 'info';
  }

  private toastForNotification(notification: Notification): void {
    const text = notification.titre || notification.message || 'Nouvelle notification';
    const lower = `${notification.titre} ${notification.message}`.toLowerCase();
    if (notification.niveau === 'alert' || lower.includes('cve') || lower.includes('critique'))
      this.toastService.warning(text);
    else if (lower.includes('scan') || notification.niveau === 'success')
      this.toastService.success(text);
    else if (notification.niveau === 'warning' || lower.includes('erreur'))
      this.toastService.error(text);
    else this.toastService.info(text);
  }
}
