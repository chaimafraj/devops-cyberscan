import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { AlertsResponse } from '../models/alert.model';

@Injectable({ providedIn: 'root' })
export class AlertService {
  constructor(private readonly http: HttpClient) {}
  getAlerts(): Observable<AlertsResponse> {
    return this.http.get<AlertsResponse>(`${environment.API_BASE_URL}/alertes/`);
  }
}
