import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { NotificationService } from './notification.service';
import { ToastService } from './toast.service';
import { environment } from '../../environments/environment';

describe('NotificationService', () => {
  let service: NotificationService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ToastService, useValue: { error: () => {}, success: () => {}, info: () => {} } },
      ],
    });
    service = TestBed.inject(NotificationService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    service.stopPolling();
    http.verify();
  });

  it('maps the backend unread_count contract to the navbar count', () => {
    let count = -1;
    service.unreadCount.subscribe((value) => (count = value));

    service.fetchUnreadCount();
    http.expectOne(`${environment.API_BASE_URL}/notifications/unread-count/`)
      .flush({ unread_count: 7 });

    expect(count).toBe(7);
  });

  it('reads and normalizes the backend notifications contract', () => {
    let notification: any;
    service.getNotifications().subscribe((items) => (notification = items[0]));
    http.expectOne(`${environment.API_BASE_URL}/notifications/`).flush({
      unread_count: 1,
      notifications: [{
        id: 3,
        type: 'success',
        title: 'Scan terminé',
        description: 'Le rapport est prêt.',
        timestamp: '2026-07-29T10:00:00Z',
        read: false,
      }],
    });
    expect(notification.titre).toBe('Scan terminé');
    expect(notification.niveau).toBe('success');
    expect(notification.lu).toBe(false);
  });
});
