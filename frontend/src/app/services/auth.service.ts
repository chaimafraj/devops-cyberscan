import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import {
  BehaviorSubject,
  finalize,
  map,
  Observable,
  shareReplay,
  tap,
  throwError,
} from 'rxjs';
import { environment } from '../../environments/environment';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiUrl = `${environment.API_BASE_URL}/auth`;
  private refreshRequest$: Observable<string> | null = null;

  /** Native signal — required for zoneless Angular change detection. */
  private readonly currentUserSignal = signal<any>(this.readUserFromStorage());
  readonly currentUser = this.currentUserSignal.asReadonly();

  /** Kept for existing RxJS consumers; always kept in sync with the signal. */
  private readonly currentUserSubject = new BehaviorSubject<any>(this.currentUserSignal());
  readonly currentUser$ = this.currentUserSubject.asObservable();

  constructor(
    private http: HttpClient,
    private router: Router,
  ) {}

  private readUserFromStorage(): any {
    const user = sessionStorage.getItem('user');
    if (!user || user === 'undefined') return null;
    try {
      return JSON.parse(user);
    } catch {
      return null;
    }
  }

  private setUserState(user: any): void {
    if (user) {
      sessionStorage.setItem('user', JSON.stringify(user));
    } else {
      sessionStorage.removeItem('user');
    }
    this.currentUserSignal.set(user);
    this.currentUserSubject.next(user);
  }

  private persistAuthSession(response: {
    access?: string;
    refresh?: string;
    user?: any;
  }): void {
    if (response.access) {
      sessionStorage.setItem('access_token', response.access);
    }
    if (response.refresh) {
      sessionStorage.setItem('refresh_token', response.refresh);
    }
    this.setUserState(response.user ?? null);
  }

  login(username: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/login/`, { username, password }).pipe(
      tap((response: any) => this.persistAuthSession(response)),
    );
  }

  register(data: {
    username: string;
    email: string;
    password: string;
    role: string;
  }): Observable<any> {
    return this.http.post(`${this.apiUrl}/register/`, data).pipe(
      tap((response: any) => this.persistAuthSession(response)),
    );
  }

  logout(): void {
    const refresh = sessionStorage.getItem('refresh_token');
    if (refresh) {
      this.http.post(`${this.apiUrl}/logout/`, { refresh }).subscribe({
        error: () => undefined,
      });
    }
    this.clearSession();
  }

  refreshAccessToken(): Observable<string> {
    if (this.refreshRequest$) return this.refreshRequest$;

    const refresh = sessionStorage.getItem('refresh_token');
    if (!refresh) {
      return throwError(() => new Error('Jeton de rafraichissement absent'));
    }

    this.refreshRequest$ = this.http
      .post<{ access?: string; refresh?: string }>(`${this.apiUrl}/refresh/`, { refresh })
      .pipe(
        map((response) => {
          if (!response.access) {
            throw new Error("La reponse de rafraichissement ne contient aucun jeton d'acces");
          }
          sessionStorage.setItem('access_token', response.access);
          if (response.refresh) {
            sessionStorage.setItem('refresh_token', response.refresh);
          }
          return response.access;
        }),
        finalize(() => {
          this.refreshRequest$ = null;
        }),
        shareReplay({ bufferSize: 1, refCount: false }),
      );

    return this.refreshRequest$;
  }

  expireSession(): void {
    this.clearSession();
  }

  private clearSession(): void {
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('refresh_token');
    this.setUserState(null);
    this.router.navigate(['/login']);
  }

  /** Re-read sessionStorage into the signal (e.g. after navigation). */
  syncUserFromStorage(): void {
    this.setUserState(this.readUserFromStorage());
  }

  getToken(): string | null {
    return sessionStorage.getItem('access_token');
  }

  getCurrentUser(): any {
    return this.currentUserSignal();
  }

  updateCurrentUser(partial: Record<string, unknown>): void {
    const current = this.getCurrentUser();
    if (!current) return;
    this.setUserState({ ...current, ...partial });
  }

  /** Explicitly set the authenticated user (login sync / tests). */
  setCurrentUser(user: any): void {
    if (user) {
      sessionStorage.setItem('access_token', sessionStorage.getItem('access_token') || 'token');
    } else {
      sessionStorage.removeItem('access_token');
    }
    this.setUserState(user);
  }

  getUserRole(): string {
    const user = this.getCurrentUser();
    return user?.role || '';
  }

  isLoggedIn(): boolean {
    return !!this.getToken();
  }

  hasRole(role: string): boolean {
    return this.getUserRole() === role;
  }

  isAdmin(): boolean {
    return this.hasRole('admin');
  }
}
