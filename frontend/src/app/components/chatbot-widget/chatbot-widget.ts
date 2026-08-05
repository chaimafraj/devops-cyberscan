import {
  ChangeDetectorRef,
  Component,
  ElementRef,
  OnDestroy,
  OnInit,
  ViewChild,
  ViewEncapsulation,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NavigationEnd, Router } from '@angular/router';
import { Subscription, filter, finalize, take, timeout } from 'rxjs';
import { AuthService } from '../../services/auth.service';
import { ChatbotRequest, ChatbotService } from '../../services/chatbot.service';
import { ChatbotContextService, ChatbotScanContext } from '../../services/chatbot-context.service';
import { DataSyncService } from '../../services/data-sync.service';

type MessageRole = 'user' | 'assistant' | 'error';
interface ResponseSection {
  key: string;
  icon: string;
  label: string;
  content: string;
}
interface ChatMessage {
  id: string;
  role: MessageRole;
  text: string;
  createdAt: string;
  sections?: ResponseSection[];
  isReport?: boolean;
  expanded?: boolean;
}
interface StoredMessage {
  id: string;
  role: MessageRole;
  text: string;
  createdAt: string;
  isReport?: boolean;
  sections?: ResponseSection[];
}

const QUICK_QUESTIONS = [
  'Pourquoi cette vulnérabilité est critique ?',
  'Quels sont les risques ?',
  'Comment la corriger ?',
  'Donne-moi les commandes Linux',
  'Explique cette CVE',
  'Quels ports dois-je fermer ?',
  'Comment corriger TLS 1.0 ?',
];
const SECTIONS = [
  { key: 'summary', icon: '📌', label: 'Résumé', aliases: ['resume', 'résumé', 'summary'] },
  {
    key: 'risk',
    icon: '⚠',
    label: 'Niveau de risque',
    aliases: ['niveau de risque', 'risque', 'risk level'],
  },
  { key: 'score', icon: '🎯', label: 'Score', aliases: ['score', 'cvss'] },
  {
    key: 'vulnerabilities',
    icon: '🛡',
    label: 'Vulnérabilités',
    aliases: ['vulnerabilites', 'vulnérabilités', 'vulnerabilities', 'cve'],
  },
  { key: 'impact', icon: '💥', label: 'Impact', aliases: ['impact', 'impacts'] },
  {
    key: 'recommendations',
    icon: '✅',
    label: 'Recommandations',
    aliases: ['recommandations', 'recommandation', 'recommendations', 'remediation'],
  },
  {
    key: 'commands',
    icon: '💻',
    label: 'Commandes Linux',
    aliases: ['commandes linux', 'commandes', 'commands', 'linux'],
  },
  {
    key: 'analysis',
    icon: '🤖',
    label: 'Analyse IA',
    aliases: ['analyse ia', 'analyse', 'ai analysis', 'analysis'],
  },
] as const;
const VISIBLE_ROUTES = ['/dashboard', '/scanner', '/historique'];
const STORAGE_KEY = 'cyberscan_chatbot_messages_v2';
const CONVERSATION_STORAGE_KEY = 'cyberscan_chatbot_conversation_id_v1';

@Component({
  selector: 'app-chatbot-widget',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './chatbot-widget.html',
  styleUrl: './chatbot-widget.scss',
  encapsulation: ViewEncapsulation.None,
})
export class ChatbotWidget implements OnInit, OnDestroy {
  @ViewChild('messagesContainer') messagesContainer?: ElementRef<HTMLDivElement>;
  @ViewChild('messageInput') messageInput?: ElementRef<HTMLTextAreaElement>;
  open = false;
  visible = false;
  loading = false;
  input = '';
  copiedMessageId: string | null = null;
  messages: ChatMessage[] = [];
  context: ChatbotScanContext = { scope: 'global', scanId: null, domaine: null, cves: [] };
  private readonly subs = new Subscription();
  private activeRequest?: Subscription;
  private lastCompletedRequestId: string | null = null;
  private conversationId: string | null = null;

  constructor(
    private readonly authService: AuthService,
    private readonly chatbotService: ChatbotService,
    private readonly contextService: ChatbotContextService,
    private readonly dataSync: DataSyncService,
    private readonly router: Router,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.messages = this.restoreMessages();
    this.conversationId = this.restoreConversationId();
    this.updateVisibility(this.router.url || '/');
    this.subs.add(
      this.authService.currentUser$.subscribe(() => this.updateVisibility(this.router.url || '/')),
    );
    this.subs.add(
      this.router.events
        .pipe(filter((event): event is NavigationEnd => event instanceof NavigationEnd))
        .subscribe((event) => {
          const url = event.urlAfterRedirects || event.url;
          this.updateVisibility(url);
          if (!this.isRouteVisible(url)) this.contextService.clearScanContext();
        }),
    );
    this.subs.add(
      this.contextService.context$.subscribe((context) => {
        this.context = context;
        this.cdr.markForCheck();
      }),
    );
    this.subs.add(
      this.dataSync.chatbotScan$.subscribe((scan) => {
        const id = Number(scan['id'] ?? scan['scan_id']);
        if (!id) return;
        const cves = Array.isArray(scan['cves']) ? scan['cves'] : [];
        this.contextService.setScanContext({ id, domaine: scan.domaine, cves });
      }),
    );
  }
  ngOnDestroy(): void {
    this.activeRequest?.unsubscribe();
    this.subs.unsubscribe();
  }
  get contextLabel(): string {
    return this.context.scope === 'single' && this.context.domaine
      ? `Scan : ${this.context.domaine}`
      : 'Historique global';
  }
  get visibleCveSuggestions(): string[] {
    if (this.context.scope !== 'single') return [];
    const asked = this.askedQuestions;
    return this.context.cves
      .map((cve) => cve.cve_id)
      .filter((id) => !!id && !asked.some((question) => question.includes(id.toLowerCase())))
      .slice(0, 2);
  }
  get visibleQuickQuestions(): string[] {
    const asked = new Set(this.askedQuestions);
    return QUICK_QUESTIONS.filter((question) => !asked.has(this.normalizeQuestion(question))).slice(
      0,
      Math.max(0, 4 - this.visibleCveSuggestions.length),
    );
  }
  private get askedQuestions(): string[] {
    return this.messages
      .filter((message) => message.role === 'user')
      .map((message) => this.normalizeQuestion(message.text));
  }

  toggle(): void {
    this.open = !this.open;
    if (this.open) {
      this.scheduleScroll();
      setTimeout(() => this.messageInput?.nativeElement.focus(), 150);
    }
  }
  close(): void {
    this.open = false;
  }
  sendQuick(question: string): void {
    if (!this.loading) this.submitQuestion(question);
  }
  sendCve(cveId: string): void {
    this.sendQuick(`Explique ${cveId}`);
  }
  send(): void {
    this.submitQuestion(this.input);
  }
  onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.send();
    }
  }
  regenerate(messageIndex: number): void {
    if (this.loading) return;
    const question = [...this.messages.slice(0, messageIndex)]
      .reverse()
      .find((message) => message.role === 'user')?.text;
    if (question) this.submitQuestion(question, true);
  }
  async copyResponse(message: ChatMessage): Promise<void> {
    try {
      await navigator.clipboard.writeText(message.text);
      this.copiedMessageId = message.id;
      setTimeout(() => {
        if (this.copiedMessageId === message.id) this.copiedMessageId = null;
      }, 1800);
    } catch {
      this.messages.push(this.createMessage('error', 'La copie est bloquée par le navigateur.'));
      this.persistMessages();
    }
  }
  toggleDetails(message: ChatMessage): void {
    message.expanded = !message.expanded;
    this.scheduleScroll();
  }
  viewReport(): void {
    const queryParams = this.context.scanId ? { scan: this.context.scanId } : undefined;
    this.close();
    void this.router.navigate(['/historique'], { queryParams });
  }
  clearHistory(): void {
    this.activeRequest?.unsubscribe();
    this.activeRequest = undefined;
    this.loading = false;
    this.messages = [];
    sessionStorage.removeItem(STORAGE_KEY);
    this.clearConversationId();
  }
  formatTime(date: string): string {
    return new Intl.DateTimeFormat('fr-FR', { hour: '2-digit', minute: '2-digit' }).format(
      new Date(date),
    );
  }
  markdownToHtml(value: string): string {
    return this.escapeHtml(value || 'Non précisé')
      .replace(/```(?:\w+)?\s*([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
      .replace(/`([^`\n]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
      .replace(/^[-*]\s+(.+)$/gm, '<span class="md-list-item">$1</span>')
      .replace(/^\d+\.\s+(.+)$/gm, '<span class="md-list-item numbered">$1</span>')
      .replace(/\n/g, '<br>');
  }

  private submitQuestion(rawQuestion: string, regenerate = false): void {
    const question = (rawQuestion || '').trim();
    if (!question || this.loading) return;
    const requestId = this.createId();
    this.input = '';
    this.loading = true;
    this.messages.push(this.createMessage('user', question));
    this.persistMessages();
    this.scheduleScroll();
    const payload: ChatbotRequest = {
      message: question,
      scope: this.context.scope,
    };
    if (this.conversationId) {
      payload.conversation_id = this.conversationId;
    } else {
      payload.new_conversation = true;
      if (this.context.scope === 'single' && this.context.scanId != null) {
        payload.scan_id = this.context.scanId;
      }
    }
    this.activeRequest = this.chatbotService
      .ask(payload)
      .pipe(
        take(1),
        timeout(60_000),
        finalize(() => {
          this.loading = false;
          this.activeRequest = undefined;
          this.cdr.markForCheck();
          this.scheduleScroll();
        }),
      )
      .subscribe({
        next: (response) => {
          if (this.lastCompletedRequestId === requestId) return;
          this.lastCompletedRequestId = requestId;
          if (response.conversation_id) this.persistConversationId(response.conversation_id);
          this.messages.push(
            this.createMessage(
              'assistant',
              response.answer.trim() || 'Aucune réponse générée.',
              undefined,
              undefined,
              response.is_report === true,
              response.sections,
            ),
          );
          this.persistMessages();
          this.scheduleScroll();
        },
        error: (error) => {
          const conversationExpired = error?.status === 404 && !!this.conversationId;
          if (conversationExpired) this.clearConversationId();
          const text =
            error?.name === 'TimeoutError'
              ? 'L’assistant met trop de temps à répondre. Réessayez dans quelques instants.'
              : conversationExpired
                ? 'Cette conversation est introuvable ou a expiré. Effacez la conversation pour en recommencer une nouvelle.'
                : this.extractError(error);
          this.messages.push(this.createMessage('error', text));
          this.persistMessages();
          this.scheduleScroll();
        },
      });
  }
  private parseSections(answer: string): ResponseSection[] {
    const buckets = new Map<string, string[]>();
    let activeKey = 'analysis';
    for (const line of answer.split(/\r?\n/)) {
      const heading = line
        .replace(/^#{1,6}\s*/, '')
        .replace(/[*_`]/g, '')
        .replace(/^[^\p{L}\p{N}]+/u, '')
        .replace(/:\s*$/, '')
        .trim()
        .toLocaleLowerCase('fr-FR');
      const definition = SECTIONS.find((section) =>
        section.aliases.some((alias) => heading === alias || heading.startsWith(`${alias} `)),
      );
      if (definition) {
        activeKey = definition.key;
        const inlineValue = line.includes(':') ? line.slice(line.indexOf(':') + 1).trim() : '';
        if (inlineValue) buckets.set(activeKey, [inlineValue]);
        continue;
      }
      const current = buckets.get(activeKey) ?? [];
      current.push(line);
      buckets.set(activeKey, current);
    }
    const analysis = (buckets.get('analysis') ?? []).join('\n').trim();
    if (!buckets.has('summary') && analysis)
      buckets.set('summary', [analysis.split(/\n\n/)[0].slice(0, 420)]);
    if (!buckets.has('risk')) {
      const risk = answer.match(/\b(critique|élevé|haut|moyen|modéré|faible)\b/i)?.[0];
      if (risk) buckets.set('risk', [risk]);
    }
    if (!buckets.has('score')) {
      const score = answer.match(/\b(?:CVSS|score)\s*:?\s*(\d+(?:[.,]\d+)?(?:\s*\/\s*10)?)/i)?.[1];
      if (score) buckets.set('score', [score.includes('/') ? score : `${score}/10`]);
    }
    return SECTIONS.map(({ key, icon, label }) => ({
      key,
      icon,
      label,
      content: (buckets.get(key) ?? []).join('\n').trim() || 'Non précisé',
    }));
  }
  private createMessage(
    role: MessageRole,
    text: string,
    id = this.createId(),
    createdAt = new Date().toISOString(),
    isReport = false,
    backendSections?: unknown,
  ): ChatMessage {
    const message: ChatMessage = { id, role, text, createdAt, isReport, expanded: false };
    if (role === 'assistant' && isReport) {
      const sections = this.normalizeBackendSections(backendSections);
      message.sections = sections.length ? sections : this.parseSections(text);
    }
    return message;
  }
  private normalizeBackendSections(raw: unknown): ResponseSection[] {
    const values: Array<{ key: string; value: unknown }> = Array.isArray(raw)
      ? raw.map((value, index) => ({
          key:
            value && typeof value === 'object'
              ? String((value as any).key ?? (value as any).title ?? (value as any).label ?? index)
              : String(index),
          value,
        }))
      : raw && typeof raw === 'object'
        ? Object.entries(raw as Record<string, unknown>).map(([key, value]) => ({ key, value }))
        : [];

    return values
      .map(({ key, value }) => {
        const item = value && typeof value === 'object' ? (value as any) : null;
        const content = String(item?.content ?? item?.text ?? item?.value ?? value ?? '').trim();
        if (!content || content === '[object Object]') return null;
        const normalizedKey = key.toLocaleLowerCase('fr-FR');
        const definition = SECTIONS.find((section) =>
          section.aliases.some(
            (alias) => normalizedKey === alias || normalizedKey.startsWith(`${alias} `),
          ),
        );
        return {
          key: definition?.key ?? normalizedKey,
          icon: String(item?.icon ?? definition?.icon ?? '•'),
          label: String(item?.label ?? item?.title ?? definition?.label ?? key),
          content,
        } satisfies ResponseSection;
      })
      .filter((section): section is ResponseSection => section !== null);
  }
  private restoreMessages(): ChatMessage[] {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      const stored = raw ? (JSON.parse(raw) as StoredMessage[]) : [];
      return Array.isArray(stored)
        ? stored
            .filter((message) => message?.id && message?.text && message?.createdAt)
            .slice(-50)
            .map((message) =>
              this.createMessage(
                message.role,
                message.text,
                message.id,
                message.createdAt,
                message.isReport === true,
                message.sections,
              ),
            )
        : [];
    } catch {
      sessionStorage.removeItem(STORAGE_KEY);
      return [];
    }
  }
  private persistMessages(): void {
    sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify(
        this.messages
          .slice(-50)
          .map(({ id, role, text, createdAt, isReport, sections }) => ({
            id,
            role,
            text,
            createdAt,
            isReport,
            sections,
          })),
      ),
    );
  }
  private restoreConversationId(): string | null {
    const value = sessionStorage.getItem(CONVERSATION_STORAGE_KEY)?.trim();
    return value || null;
  }
  private persistConversationId(conversationId: string): void {
    this.conversationId = conversationId;
    sessionStorage.setItem(CONVERSATION_STORAGE_KEY, conversationId);
  }
  private clearConversationId(): void {
    this.conversationId = null;
    sessionStorage.removeItem(CONVERSATION_STORAGE_KEY);
  }
  private scheduleScroll(): void {
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        const container = this.messagesContainer?.nativeElement;
        if (container) container.scrollTo({ top: container.scrollHeight, behavior: 'smooth' });
      }),
    );
  }
  private extractError(error: any): string {
    const body = error?.error;
    if (typeof body === 'string' && body.trim()) return body;
    if (body?.error) return String(body.error);
    if (body?.detail) return String(body.detail);
    if (body?.message) return String(body.message);
    if (error?.status === 0)
      return 'Impossible de joindre le serveur. Vérifiez que le backend est démarré.';
    if (error?.status === 401 || error?.status === 403)
      return 'Votre session a expiré ou vous ne disposez pas des droits nécessaires.';
    return `Erreur HTTP ${error?.status || ''} lors de l’appel à l’assistant IA.`.trim();
  }
  private escapeHtml(value: string): string {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
  private normalizeQuestion(value: string): string {
    return (value || '').trim().toLocaleLowerCase('fr-FR');
  }
  private createId(): string {
    return typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }
  private isRouteVisible(url: string): boolean {
    const path = (url || '').split('?')[0];
    return VISIBLE_ROUTES.some((route) => path === route || path.startsWith(`${route}/`));
  }
  private updateVisibility(url: string): void {
    this.visible = this.authService.isLoggedIn() && this.isRouteVisible(url);
    if (!this.visible) this.open = false;
    this.cdr.markForCheck();
  }
}




