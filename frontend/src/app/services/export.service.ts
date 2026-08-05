import { environment } from '../../environments/environment';
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ExportService {
  private apiUrl = environment.API_BASE_URL + '';

  constructor(private http: HttpClient) {}

  downloadPdf(scanId: number, vulnerabilities: readonly unknown[] = []): Observable<Blob> {
    return this.http.post(`${this.apiUrl}/scans/${scanId}/export/pdf/`, { vulnerabilities }, { responseType: 'blob' });
  }

  downloadExcel(scanId: number): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/scans/${scanId}/export/excel/`, { responseType: 'blob' });
  }

  downloadJson(scanId: number): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/scans/${scanId}/export/json/`, { responseType: 'blob' });
  }

  triggerDownload(blob: Blob, filename: string) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }
}


