import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getToken();
  const isTokenRequest = /\/auth\/(login|register|refresh)\//.test(req.url);

  const authReq = token && !isTokenRequest
    ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : req;

  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status !== 401 || isTokenRequest || !token) {
        return throwError(() => error);
      }

      return authService.refreshAccessToken().pipe(
        switchMap((accessToken) =>
          next(req.clone({
            setHeaders: { Authorization: `Bearer ${accessToken}` },
          })),
        ),
        catchError((refreshError) => {
          authService.expireSession();
          return throwError(() => refreshError);
        }),
      );
    }),
  );
};
