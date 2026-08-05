import { Scan } from './history.model';

export interface DashboardStats {
  total_scans: number;
  critical_count: number;
  medium_count: number;
  total_recommandations?: number;
  total_cve?: number;
  recent_scans: Scan[];
}
