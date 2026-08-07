import { CommonModule } from '@angular/common';
import {
  ChangeDetectorRef,
  Component,
  ElementRef,
  HostListener,
  OnDestroy,
  OnInit,
  effect,
  inject,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import {
  NavigationEnd,
  NavigationStart,
  Router,
  RouterLink,
  RouterLinkActive,
} from '@angular/router';
import { Subscription, filter } from 'rxjs';

import { AuthService } from '../../services/auth.service';
import { DataSyncService } from '../../services/data-sync.service';
import { Notification, NotificationService } from '../../services/notification.service';

@Component({
  selector: 'app-navbar',
  imports: [RouterLink, RouterLinkActive, CommonModule],
  templateUrl: './navbar.html',
  styleUrl: './navbar.scss',
  standalone: true,
})
export class Navbar implements OnInit, OnDestroy {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly notifService = inject(NotificationService);
  private readonly dataSync = inject(DataSyncService);
  private readonly elementRef = inject(ElementRef<HTMLElement>);
  private readonly cdr = inject(ChangeDetectorRef);

  /** Direct auth signal — updates the view immediately after login (zoneless-safe). */
  readonly currentUser = this.authService.currentUser;
  readonly unreadCount = toSignal(this.notifService.unreadCount, { initialValue: 0 });
  readonly notifications = toSignal(this.notifService.notifications$, {
    initialValue: [] as Notification[],
  });

  isDark = true;
  isMenuOpen = false;
  isNotificationsOpen = false;
  notificationsLoading = false;
  notificationsError = '';

  private refreshSub?: Subscription;
  private routeSub?: Subscription;

  constructor() {
    effect(() => {
      const user = this.currentUser();
      if (user) {
        this.notifService.startPolling();
      } else {
        this.notifService.stopPolling();
        this.isNotificationsOpen = false;
      }
    });
  }

  ngOnInit(): void {
    const savedTheme = sessionStorage.getItem('theme') || 'dark';
    this.isDark = savedTheme === 'dark';
    document.body.setAttribute('data-theme', savedTheme);

    // Ensure session is reflected even if login happened before this view checked.
    this.authService.syncUserFromStorage();

    this.routeSub = this.router.events
      .pipe(filter((event) => event instanceof NavigationStart || event instanceof NavigationEnd))
      .subscribe((event) => {
        if (event instanceof NavigationStart) {
          this.isNotificationsOpen = false;
          this.isMenuOpen = false;
        }
        if (event instanceof NavigationEnd) {
          this.authService.syncUserFromStorage();
        }
        this.cdr.markForCheck();
      });

    this.refreshSub = this.dataSync.notificationsRefresh$.subscribe(() => {
      if (this.isNotificationsOpen) this.loadNotifications();
      else this.notifService.fetchUnreadCount(true);
    });
  }

  ngOnDestroy(): void {
    this.refreshSub?.unsubscribe();
    this.routeSub?.unsubscribe();
  }

  toggleNotifications(event: MouseEvent): void {
    event.stopPropagation();
    this.isNotificationsOpen = !this.isNotificationsOpen;
    if (this.isNotificationsOpen) this.loadNotifications();
  }

  loadNotifications(): void {
    this.notificationsLoading = true;
    this.notificationsError = '';
    this.notifService.getNotifications().subscribe({
      next: () => {
        this.notificationsLoading = false;
        this.cdr.markForCheck();
      },
      error: () => {
        this.notificationsLoading = false;
        this.notificationsError = 'Impossible de charger les notifications.';
        this.cdr.markForCheck();
      },
    });
  }

  markNotificationAsRead(notification: Notification): void {
    if (notification.lu) return;
    this.notifService.markAsRead(notification.id).subscribe({
      error: () => {
        this.notificationsError = 'Impossible de marquer cette notification comme lue.';
        this.cdr.markForCheck();
      },
    });
  }

  markAllNotificationsAsRead(event: MouseEvent): void {
    event.stopPropagation();
    if ((this.unreadCount() ?? 0) === 0) return;
    this.notifService.markAllAsRead().subscribe({
      error: () => {
        this.notificationsError = 'Impossible de marquer les notifications comme lues.';
        this.cdr.markForCheck();
      },
    });
  }

  notificationIcon(type: Notification['niveau']): string {
    if (type === 'alert') return '!';
    if (type === 'warning') return '⚠';
    if (type === 'success') return '✓';
    return 'i';
  }

  trackNotification(_index: number, notification: Notification): number {
    return notification.id;
  }

  @HostListener('document:click', ['$event'])
  closeNotificationsOnOutsideClick(event: MouseEvent): void {
    if (!this.isNotificationsOpen) return;

    const notificationCenter =
      this.elementRef.nativeElement.querySelector<HTMLElement>('.notification-center');
    const target = event.target;
    if (!(target instanceof Node) || !notificationCenter?.contains(target)) {
      this.isNotificationsOpen = false;
      this.cdr.markForCheck();
    }
  }

  @HostListener('document:keydown.escape')
  closeNotificationsOnEscape(): void {
    this.isNotificationsOpen = false;
    this.cdr.markForCheck();
  }

  toggleTheme(): void {
    this.isDark = !this.isDark;
    const theme = this.isDark ? 'dark' : 'light';
    sessionStorage.setItem('theme', theme);
    document.body.setAttribute('data-theme', theme);
  }

  toggleMenu(): void {
    this.isMenuOpen = !this.isMenuOpen;
  }

  closeMenu(): void {
    this.isMenuOpen = false;
  }

  logout(): void {
    this.isNotificationsOpen = false;
    this.authService.logout();
  }
}
