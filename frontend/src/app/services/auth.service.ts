import { Injectable } from '@angular/core';
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
  private currentUserSubject = new BehaviorSubject<any>(this.getUserFromStorage());
  private refreshRequest$: Observable<string> | null = null;

  currentUser$ = this.currentUserSubject.asObservable();

  constructor(
    private http: HttpClient,
    private router: Router,
  ) {}

  private getUserFromStorage(): any {
    const user = sessionStorage.getItem('user');
    if (!user || user === 'undefined') return null;
    try {
      return JSON.parse(user);
    } catch {
      return null;
    }
  }

  login(username: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/login/`, { username, password }).pipe(
      tap((response: any) => {
        sessionStorage.setItem('access_token', response.access);
        sessionStorage.setItem('refresh_token', response.refresh);
        sessionStorage.setItem('user', JSON.stringify(response.user));
        this.currentUserSubject.next(response.user);
      }),
    );
  }

  register(data: {
    username: string;
    email: string;
    password: string;
    role: string;
  }): Observable<any> {
    return this.http.post(`${this.apiUrl}/register/`, data).pipe(
      tap((response: any) => {
        sessionStorage.setItem('access_token', response.access);
        sessionStorage.setItem('refresh_token', response.refresh);
        sessionStorage.setItem('user', JSON.stringify(response.user));
        this.currentUserSubject.next(response.user);
      }),
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
    sessionStorage.removeItem('user');
    this.currentUserSubject.next(null);
    this.router.navigate(['/login']);
  }

  getToken(): string | null {
    return sessionStorage.getItem('access_token');
  }

  getCurrentUser(): any {
    return this.currentUserSubject.value;
  }

  updateCurrentUser(partial: Record<string, unknown>): void {
    const current = this.getCurrentUser();
    if (!current) return;

    const updated = { ...current, ...partial };
    sessionStorage.setItem('user', JSON.stringify(updated));
    this.currentUserSubject.next(updated);
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
