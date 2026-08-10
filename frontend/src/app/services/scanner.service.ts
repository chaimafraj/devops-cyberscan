import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ScanResponse } from '../models/scan.model';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root',
})
export class ScannerService {
  private apiUrl = `${environment.API_BASE_URL}/scans/`;

  constructor(private http: HttpClient) {}

  // 🆕 1. Hadhi l blassa el s7i7a mta3 getDashboardStats dakhil el class!
  getDashboardStats(): Observable<any> {
    return this.http.get<any>(`${environment.API_BASE_URL}/dashboard-stats/`);
  }

  // 2. El HTTP POST call mta3 el scan
  // options : map { zap, nuclei, nvd, ... } reflétant l'état des cases à cocher
  demarrerScan(
    url: string,
    options: Record<string, boolean> = {},
  ): Observable<ScanResponse> {
    return this.http.post<ScanResponse>(this.apiUrl, { url: url, options: options });
  }

  getScan(scanId: number): Observable<any> {
    return this.http.get<any>(this.apiUrl + scanId + '/');
  }

  cancelScan(scanId: number): Observable<{ scan_id: number; status: string; message: string }> {
    return this.http.post<{ scan_id: number; status: string; message: string }>(
      this.apiUrl + scanId + '/cancel/',
      {},
    );
  }

  getRecentScans(): Observable<{ results: any[] }> {
    return this.http.get<{ results: any[] }>(this.apiUrl, {
      params: { page: '1', page_size: '10' },
    });
  }

  getVulnTemplates(): Observable<any> {
    return this.http.get<any>(`${environment.API_BASE_URL}/vuln-templates/`);
  }

  getVulnManuelles(scanId: number): Observable<any[]> {
    return this.http.get<any[]>(`${environment.API_BASE_URL}/scans/${scanId}/vulnerabilites/`);
  }

  addVulnManuelle(scanId: number, data: any): Observable<any> {
    return this.http.post(`${environment.API_BASE_URL}/scans/${scanId}/vulnerabilites/`, data);
  }

  deleteVulnManuelle(id: number): Observable<any> {
    return this.http.delete(`${environment.API_BASE_URL}/vulnerabilites/${id}/`);
  }

  /** Métadonnées + contenu structuré du rapport (génère le PDF si absent) */
  getRapport(scanId: number): Observable<any> {
    return this.http.get<any>(`${environment.API_BASE_URL}/scans/${scanId}/rapport/`);
  }

  /** Téléchargement binaire du PDF */
  downloadRapportPdf(scanId: number, forceRegenerate = false): Observable<Blob> {
    return this.http.get(`${environment.API_BASE_URL}/scans/${scanId}/rapport/download/`, {
      responseType: 'blob',
      params: forceRegenerate ? { force_regenerate: 'true' } : {},
    });
  }

  /** QR Code SVG du rapport */
  getReportQr(scanId: number): Observable<Blob> {
    return this.http.get(
      `${environment.API_BASE_URL}/scans/${scanId}/rapport/qr/`,
      { responseType: 'blob' },
    );
  }
  /** Envoi / renvoi du rapport par email (PDF en pièce jointe) */
  sendRapportEmail(scanId: number, email?: string, forceRegenerate = false): Observable<any> {
    const body = email ? { email } : {};
    return this.http.post(`${environment.API_BASE_URL}/scans/${scanId}/rapport/email/`, body, {
      params: forceRegenerate ? { force_regenerate: 'true' } : {},
    });
  }
}
