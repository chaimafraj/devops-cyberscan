import { DataSyncService } from './data-sync.service';
import { SiteReport } from '../models/scan.model';

describe('DataSyncService', () => {
  let service: DataSyncService;

  beforeEach(() => {
    service = new DataSyncService();
  });

  it('diffuse une seule invalidation ciblée après un scan terminé', () => {
    const calls = { dashboard: 0, history: 0, alerts: 0, notifications: 0, chatbot: 0 };
    service.dashboardRefresh$.subscribe(() => calls.dashboard++);
    service.historyRefresh$.subscribe(() => calls.history++);
    service.alertsRefresh$.subscribe(() => calls.alerts++);
    service.notificationsRefresh$.subscribe(() => calls.notifications++);
    service.chatbotScan$.subscribe(() => calls.chatbot++);
    const scan: SiteReport = { id: 42, domaine: 'example.com', score_risque_ia: 7 };
    service.scanCompleted(scan);
    expect(calls).toEqual({ dashboard: 1, history: 1, alerts: 1, notifications: 1, chatbot: 1 });
    expect(service.lastCompletedScan()).toBe(scan);
    expect(service.scanRevision()).toBe(1);
  });

  it('ne recharge pas le chatbot lors de la suppression d’un scan', () => {
    let chatbotCalls = 0;
    let dashboardCalls = 0;
    service.chatbotScan$.subscribe(() => chatbotCalls++);
    service.dashboardRefresh$.subscribe(() => dashboardCalls++);
    service.scanDeleted();
    expect(dashboardCalls).toBe(1);
    expect(chatbotCalls).toBe(0);
  });
});
