import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Client {
  id: number;
  nom: string;
  email: string;
  is_active: boolean;
  must_change_password: boolean;
  date_creation: string;
  nb_sites: number;
}

export interface ClientsResponse {
  results: Client[];
  count: number;
  total_pages: number;
  current_page: number;
}

@Injectable({ providedIn: 'root' })
export class ClientService {
  private apiUrl = 'http://127.0.0.1:8000/api/clients';
  private sitesUrl = 'http://127.0.0.1:8000/api/sites';

  constructor(private http: HttpClient) {}

  getClients(page: number = 1, pageSize: number = 10): Observable<ClientsResponse> {
    return this.http.get<ClientsResponse>(`${this.apiUrl}/?page=${page}&page_size=${pageSize}`);
  }

  createClient(nom: string, username: string, email: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/`, { nom, username, email });
  }

  deleteClient(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}/`);
  }

  getMySites(): Observable<any[]> {
    return this.http.get<any[]>(`${this.sitesUrl}/`);
  }

  addSite(domaine: string): Observable<any> {
    return this.http.post(`${this.sitesUrl}/`, { domaine });
  }

  deleteSite(id: number): Observable<any> {
    return this.http.delete(`${this.sitesUrl}/${id}/`);
  }
}
