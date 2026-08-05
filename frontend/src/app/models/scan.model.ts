// Modèles / interfaces pour les résultats de scan CyberScan

export type ZapRisk = 'High' | 'Medium' | 'Low' | 'Informational' | string;

// Une alerte OWASP ZAP telle que retournée par l'API Django
export interface ZapFinding {
  name: string;
  risk: ZapRisk;
  url: string;
  description: string;
  solution: string;
}

// Un protocole SSL/TLS détecté
export interface ProtocolResult {
  name: string;
  status: 'secure' | 'obsolete' | 'vulnerable' | string;
}

// Le rapport pour un site (élément de rapport[])
export interface SiteReport {
  domaine?: string;
  protocols?: ProtocolResult[];
  vulnerabilities?: string[];
  score_risque_ia?: number;
  zap_findings?: ZapFinding[];
  [key: string]: any; // champs additionnels renvoyés par l'API
}

// La réponse globale de POST /api/scans/
export interface QueuedScan {
  scan_id: number;
  task_id: string;
  domaine: string;
  status: 'PENDING' | 'RUNNING';
  status_url: string;
}

export interface ScanResponse {
  scans?: QueuedScan[];
  tracking_ids?: number[];
  rapport?: SiteReport[];
  zap_findings?: ZapFinding[]; // ZAP peut aussi être renvoyé à la racine
  [key: string]: any;
}
