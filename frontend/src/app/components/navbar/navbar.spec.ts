import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, Subject } from 'rxjs';

import { Notification, NotificationService } from '../../services/notification.service';

import { Navbar } from './navbar';

describe('Navbar', () => {
  let component: Navbar;
  let fixture: ComponentFixture<Navbar>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Navbar],
      providers: [provideRouter([])],
    }).compileComponents();

    fixture = TestBed.createComponent(Navbar);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('keeps the notifications panel closed until the bell is clicked', () => {
    fixture.detectChanges();

    expect(component.isNotificationsOpen).toBe(false);
    expect(fixture.nativeElement.querySelector('.notifications-panel')).toBeNull();
  });

  it('opens the notifications panel and loads recent notifications', () => {
    const notificationService = TestBed.inject(NotificationService);
    const load = vi.spyOn(notificationService, 'getNotifications').mockReturnValue(of([]));
    const event = { stopPropagation: vi.fn() } as unknown as MouseEvent;

    component.toggleNotifications(event);

    expect(component.isNotificationsOpen).toBe(true);
    expect(load).toHaveBeenCalledOnce();
  });

  it('refreshes the notifications list when loading finishes without another click', () => {
    const notificationService = TestBed.inject(NotificationService);
    const response$ = new Subject<Notification[]>();
    vi.spyOn(notificationService, 'getNotifications').mockReturnValue(response$);
    component.currentUser = { username: 'test' };
    component.toggleNotifications({ stopPropagation: vi.fn() } as unknown as MouseEvent);
    fixture.detectChanges();

    expect(fixture.nativeElement.textContent).toContain('Chargement des notifications');

    response$.next([]);
    response$.complete();

    expect(fixture.nativeElement.textContent).toContain('Aucune notification');
    expect(fixture.nativeElement.textContent).not.toContain('Chargement des notifications');
  });

  it('closes the notifications panel when another navbar control is clicked', () => {
    component.isNotificationsOpen = true;
    fixture.detectChanges();
    const target = fixture.nativeElement.querySelector('.theme-toggle') as HTMLElement;

    component.closeNotificationsOnOutsideClick({ target } as unknown as MouseEvent);

    expect(component.isNotificationsOpen).toBe(false);
  });
});
