import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface ChatbotCve {
  cve_id: string;
  description?: string;
  cvss_score?: number;
}

export interface ChatbotScanContext {
  scope: 'single' | 'global';
  scanId: number | null;
  domaine: string | null;
  cves: ChatbotCve[];
}

const GLOBAL_CONTEXT: ChatbotScanContext = {
  scope: 'global',
  scanId: null,
  domaine: null,
  cves: [],
};
const CONTEXT_STORAGE_KEY = 'cyberscan_chatbot_context_v1';

@Injectable({ providedIn: 'root' })
export class ChatbotContextService {
  private readonly contextSubject = new BehaviorSubject<ChatbotScanContext>(this.restoreContext());
  readonly context$ = this.contextSubject.asObservable();

  get context(): ChatbotScanContext {
    return this.contextSubject.value;
  }

  /** Active le mode scan précis (détail d'un scan). */
  setScanContext(scan: { id: number; domaine?: string; cves?: ChatbotCve[] } | null): void {
    if (!scan?.id) {
      this.clearScanContext();
      return;
    }
    this.contextSubject.next({
      scope: 'single',
      scanId: scan.id,
      domaine: scan.domaine || `scan #${scan.id}`,
      cves: Array.isArray(scan.cves) ? scan.cves : [],
    });
    sessionStorage.setItem(CONTEXT_STORAGE_KEY, JSON.stringify(this.contextSubject.value));
  }

  /** Repasse en historique global. */
  clearScanContext(): void {
    this.contextSubject.next({ ...GLOBAL_CONTEXT });
    sessionStorage.removeItem(CONTEXT_STORAGE_KEY);
  }

  private restoreContext(): ChatbotScanContext {
    try {
      const raw = sessionStorage.getItem(CONTEXT_STORAGE_KEY);
      if (!raw) return { ...GLOBAL_CONTEXT };
      const context = JSON.parse(raw) as ChatbotScanContext;
      return context?.scope === 'single' && context.scanId
        ? { ...context, cves: Array.isArray(context.cves) ? context.cves : [] }
        : { ...GLOBAL_CONTEXT };
    } catch {
      return { ...GLOBAL_CONTEXT };
    }
  }
}
