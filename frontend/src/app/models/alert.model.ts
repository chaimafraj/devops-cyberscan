export interface Alert {
  id: number;
  titre?: string;
  type?: string;
  icon?: string;
  message?: string;
  domaine?: string;
  niveau?: 'critique' | 'moyenne' | 'faible' | string;
  date_creation?: string;
  date?: string;
  lue?: boolean;
}

export interface AlertStats {
  critiques: number;
  moyennes: number;
  faibles: number;
  total: number;
}

export interface AlertsResponse {
  alertes: Alert[];
  stats: AlertStats;
}

