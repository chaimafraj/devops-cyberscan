import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { ManualVulnerability, ScanPage } from '../models/history.model';

@Injectable({ providedIn: 'root' })
export class HistoryService {
  private readonly scansUrl = environment.API_BASE_URL + '/scans';
  constructor(private readonly http: HttpClient) {}
  getScans(page: number, pageSize: number, search = "", risk = ""): Observable<ScanPage> {
    let params = new HttpParams().set('page', page).set('page_size', pageSize);
    if (search.trim()) params = params.set('search', search.trim());
    if (risk) params = params.set('risk', risk.toUpperCase());
    return this.http.get<ScanPage>(this.scansUrl + '/', { params });
  }
  deleteScan(id: number): Observable<void> { return this.http.delete<void>(this.scansUrl + '/' + id + '/'); }
  getManualVulnerabilities(scanId: number): Observable<ManualVulnerability[]> { return this.http.get<ManualVulnerability[]>(this.scansUrl + '/' + scanId + '/vulnerabilites/'); }
  deleteManualVulnerability(id: number): Observable<void> { return this.http.delete<void>(environment.API_BASE_URL + '/vulnerabilites/' + id + '/'); }
}
