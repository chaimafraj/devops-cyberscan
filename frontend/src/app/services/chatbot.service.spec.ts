import { describe, expect, it } from 'vitest';
import { of } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { ChatbotService } from './chatbot.service';

describe('ChatbotService', () => {
  it('lit le contrat backend actuel et donne priorité à answer', () => {
    const sections = { summary: 'Résumé du scan', risk: 'Élevé' };
    const http = {
      post: () =>
        of({
          answer: 'Réponse actuelle',
          reply: 'Ancien alias',
          context_mode: 'single',
          conversation_id: 8,
          is_report: true,
          question: 'Analyse ce scan',
          scan_id: 42,
          sections,
        }),
    } as unknown as HttpClient;
    const service = new ChatbotService(http);
    let result: any;

    service
      .ask({ message: 'Analyse ce scan', scope: 'single', scan_id: 42, new_conversation: true })
      .subscribe((response) => (result = response));

    expect(result).toEqual({
      conversation_id: '8',
      answer: 'Réponse actuelle',
      context_mode: 'single',
      is_report: true,
      question: 'Analyse ce scan',
      scan_id: 42,
      sections,
    });
  });

  it('ne transforme pas les champs optionnels absents d’une réponse 200 en erreur', () => {
    const http = { post: () => of({ answer: 'Réponse simple', is_report: false }) } as unknown as HttpClient;
    const service = new ChatbotService(http);
    let result: any;
    let error: unknown;

    service.ask({ message: 'Suite', scope: 'global' }).subscribe({
      next: (response) => (result = response),
      error: (value) => (error = value),
    });

    expect(error).toBeUndefined();
    expect(result).toEqual({
      answer: 'Réponse simple',
      context_mode: undefined,
      is_report: false,
      question: undefined,
      scan_id: null,
      sections: undefined,
    });
  });
});


