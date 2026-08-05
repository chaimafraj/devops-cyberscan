import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { ApiMessage } from '../models/api.model';
import { ChangePasswordRequest } from '../models/auth.model';

@Injectable({ providedIn: 'root' })
export class ProfileService {
  constructor(private readonly http: HttpClient) {}
  changePassword(request: ChangePasswordRequest): Observable<ApiMessage> {
    return this.http.post<ApiMessage>(`${environment.API_BASE_URL}/auth/change-password/`, request);
  }
}
