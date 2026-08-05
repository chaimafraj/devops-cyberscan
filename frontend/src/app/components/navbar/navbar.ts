import { CommonModule } from '@angular/common';
import {
  ChangeDetectorRef,
  Component,
  ElementRef,
  HostListener,
  OnDestroy,
  OnInit,
} from '@angular/core';
import { NavigationStart, Router, RouterLink, RouterLinkActive } from '@angular/router';
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
  isDark = true;
  isMenuOpen = false;
  isNotificationsOpen = false;
  notificationsLoading = false;
  notificationsError = '';
  currentUser: any = null;
  unreadCount = 0;
  notifications: Notification[] = [];

  private authSub?: Subscription;
  private unreadSub?: Subscription;
  private notificationsSub?: Subscription;
  private refreshSub?: Subscription;
  private routeSub?: Subscription;

  constructor(
    private readonly authService: AuthService,
    private readonly router: Router,
    private readonly notifService: NotificationService,
    private readonly dataSync: DataSyncService,
    private readonly elementRef: ElementRef<HTMLElement>,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    const savedTheme = sessionStorage.getItem('theme') || 'dark';
    this.isDark = savedTheme === 'dark';
    document.body.setAttribute('data-theme', savedTheme);

    this.routeSub = this.router.events
      .pipe(filter((event) => event instanceof NavigationStart))
      .subscribe(() => {
        this.isNotificationsOpen = false;
        this.isMenuOpen = false;
      });

    this.authSub = this.authService.currentUser$.subscribe((user) => {
      this.currentUser = user;
      if (user) {
        this.notifService.startPolling();
      } else {
        this.notifService.stopPolling();
        this.unreadCount = 0;
        this.notifications = [];
        this.isNotificationsOpen = false;
      }
    });

    this.unreadSub = this.notifService.unreadCount.subscribe((count) => {
      this.unreadCount = count;
    });
    this.notificationsSub = this.notifService.notifications$.subscribe((notifications) => {
      this.notifications = notifications;
    });
    this.refreshSub = this.dataSync.notificationsRefresh$.subscribe(() => {
      if (this.isNotificationsOpen) this.loadNotifications();
      else this.notifService.fetchUnreadCount(true);
    });
  }

  ngOnDestroy(): void {
    this.authSub?.unsubscribe();
    this.unreadSub?.unsubscribe();
    this.notificationsSub?.unsubscribe();
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
        this.cdr.detectChanges();
      },
      error: () => {
        this.notificationsLoading = false;
        this.notificationsError = 'Impossible de charger les notifications.';
        this.cdr.detectChanges();
      },
    });
  }

  markNotificationAsRead(notification: Notification): void {
    if (notification.lu) return;
    this.notifService.markAsRead(notification.id).subscribe({
      error: () => {
        this.notificationsError = 'Impossible de marquer cette notification comme lue.';
      },
    });
  }

  markAllNotificationsAsRead(event: MouseEvent): void {
    event.stopPropagation();
    if (this.unreadCount === 0) return;
    this.notifService.markAllAsRead().subscribe({
      error: () => {
        this.notificationsError = 'Impossible de marquer les notifications comme lues.';
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
    }
  }

  @HostListener('document:keydown.escape')
  closeNotificationsOnEscape(): void {
    this.isNotificationsOpen = false;
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
