import { ProtocolResult } from './scan.model';

export interface Technology { name: string; version?: string[]; }
export interface Cve { id?: number | string; cve_id: string; cvss_score?: number; cvssScore?: number; score?: number; description?: string; recommandation_ia?: string; severity?: string; baseSeverity?: string; severite?: string; date_publication?: string; published?: string; publishedDate?: string; }
export interface ManualVulnerability { id: number; nom: string; type_vuln?: string; cvss_score?: number; risk?: string; steps?: string[]; etapes_correction?: string[] | string; composant?: string; impacted_element?: string; url?: string; preuve?: string; proof_of_concept?: string; evidence?: string; type?: string; name?: string; actifs?: string; assets?: string; sourceMenace?: string; source_menace?: string; source?: string; complexiteExploitation?: string; complexite_exploitation?: string; cvss?: number; probabilite?: string; probability?: string; criticite?: string; severity?: string; recommandation?: string; solution?: string; complexiteMiseEnOeuvre?: string; complexite_mise_en_oeuvre?: string; complexite?: string; prioriteMiseEnOeuvre?: string; priorite_mise_en_oeuvre?: string; priorite?: string; cve_id?: string; }
export interface ScanResults { protocols?: ProtocolResult[]; vulnerabilities?: Array<string | ManualVulnerability>; zap_findings?: ManualVulnerability[]; nvd_cves?: Cve[]; nmap?: string; openssl?: string; sslscan?: string; whatweb?: { technologies?: Technology[] }; }
export type ReportStatus = 'non_genere' | 'generation' | 'pret' | 'erreur';
export type EmailStatus = 'non_envoye' | 'envoi' | 'envoye' | 'erreur';
export interface Scan {
  id: number;
  domaine: string;
  date_scan: string;
  score_risque_ia: number;
  status?: string;
  error_message?: string;
  client_nom?: string;
  protocols_count?: number;
  protocols?: ProtocolResult[];
  resultats_ssl?: ScanResults;
  whatweb?: { technologies?: Technology[] };
  cves?: Cve[];
  vulnerabilites?: Array<string | ManualVulnerability>;
  vulnerabilities?: Array<string | ManualVulnerability>;
  vulns_manuelles?: ManualVulnerability[];
  vulnerabilites_manuelles?: ManualVulnerability[];
  pdf_disponible?: boolean;
  has_rapport?: boolean;
  rapport_status?: ReportStatus;
  rapportStatus?: ReportStatus;
  email_status?: EmailStatus;
  emailStatus?: EmailStatus;
}
export interface ScanView extends Scan {
  riskClass: string;
  statut: string;
  rapportStatus: ReportStatus;
  emailStatus: EmailStatus;
  pdfGenerating: boolean;
  pdfDownloading: boolean;
  emailSending: boolean;
  rapportIncomplete: boolean;
}
export interface ScanPage { results: Scan[]; count?: number; total?: number; total_pages?: number; page?: number; }
export interface EmailReportResponse { recipients?: string[]; message?: string; }
export interface ProtocolDetail { titre: string; description: string; risque: string; solution: string; recommandation_ia?: string; }


