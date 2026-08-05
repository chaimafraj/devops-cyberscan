import { environment } from '../../environments/environment';
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map } from 'rxjs';

export interface ChatbotRequest {
  message: string;
  scope: 'single' | 'global';
  scan_id?: number;
  conversation_id?: string;
  new_conversation?: true;
  regenerate?: true;
}

export interface ChatbotResponse {
  conversation_id?: string;
  answer: string;
  context_mode?: string;
  is_report: boolean;
  question?: string;
  scan_id?: number | null;
  sections?: unknown;
}

@Injectable({ providedIn: 'root' })
export class ChatbotService {
  private apiUrl = environment.API_BASE_URL + '/chatbot/';

  constructor(private http: HttpClient) {}

  ask(payload: ChatbotRequest): Observable<ChatbotResponse> {
    return this.http.post<unknown>(this.apiUrl, payload).pipe(
      map((raw) => {
        const response = this.asResponseObject(raw);
        const conversationId = this.readConversationId(
          response['conversation_id'] ?? payload.conversation_id,
        );

        return {
          ...(conversationId ? { conversation_id: conversationId } : {}),
          answer: this.extractAnswer(response),
          context_mode: this.readString(response['context_mode']),
          is_report: response['is_report'] === true,
          question: this.readString(response['question']),
          scan_id: this.readScanId(response['scan_id'] ?? payload.scan_id),
          sections: response['sections'],
        };
      }),
    );
  }

  private asResponseObject(raw: unknown): Record<string, unknown> {
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
      const response = raw as Record<string, unknown>;
      const data = response['data'];
      return data && typeof data === 'object' && !Array.isArray(data)
        ? ({ ...response, ...(data as Record<string, unknown>) } as Record<string, unknown>)
        : response;
    }
    return typeof raw === 'string' ? { answer: raw } : {};
  }

  private extractAnswer(response: Record<string, unknown>): string {
    // `answer` est le champ du contrat backend actuel. Les alias restent des replis temporaires.
    const value =
      response['answer'] ?? response['reply'] ?? response['response'] ?? response['message'];
    if (Array.isArray(value)) {
      return value
        .map((chunk) => {
          if (typeof chunk === 'string') return chunk;
          if (!chunk || typeof chunk !== 'object') return '';
          const item = chunk as Record<string, unknown>;
          return this.readString(item['token'] ?? item['text'] ?? item['content']) ?? '';
        })
        .join('')
        .trim();
    }
    return this.readString(value) ?? '';
  }

  private readString(value: unknown): string | undefined {
    return typeof value === 'string' && value.trim() ? value.trim() : undefined;
  }

  private readConversationId(value: unknown): string | undefined {
    if (typeof value === 'number' && Number.isInteger(value) && value > 0) {
      return String(value);
    }
    return this.readString(value);
  }

  private readScanId(value: unknown): number | null {
    const scanId = Number(value);
    return Number.isFinite(scanId) ? scanId : null;
  }
}

