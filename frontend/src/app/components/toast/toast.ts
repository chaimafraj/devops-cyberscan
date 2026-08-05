import { ChangeDetectionStrategy, Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ToastService, Toast } from '../../services/toast.service';
import { Observable } from 'rxjs';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'app-toast',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="toast-container" role="region" aria-label="Notifications" aria-live="polite" aria-atomic="false">
      @for (toast of toasts$ | async; track toast.id) {
        <div class="cyber-toast" [ngClass]="toast.type" [attr.role]="toast.type === 'error' ? 'alert' : 'status'">
          <span class="toast-icon">
            @switch (toast.type) {
              @case ('success') { ✓ }
              @case ('error') { ⚠ }
              @case ('warning') { ⚡ }
              @case ('info') { ℹ }
            }
          </span>
          <span class="toast-msg">{{ toast.message }}</span>
          <button type="button" class="toast-dismiss" aria-label="Fermer la notification" (click)="dismiss(toast.id); $event.stopPropagation()">✕</button>
        </div>
      }
    </div>
  `,
  styles: [`
    .toast-container {
      position: fixed;
      top: 70px;
      right: 20px;
      z-index: 10000;
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-width: 420px;
    }
    .cyber-toast {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      border: 1px solid;
      font-family: 'Share Tech Mono', monospace;
      font-size: 12px;
      letter-spacing: 1px;
      cursor: pointer;
      animation: slideIn 0.3s ease;
      backdrop-filter: blur(10px);
    }
    .cyber-toast.success {
      background: rgba(0, 255, 65, 0.12);
      border-color: #00FF41;
      color: #00FF41;
    }
    .cyber-toast.error {
      background: rgba(255, 68, 68, 0.12);
      border-color: #ff4444;
      color: #ff4444;
    }
    .cyber-toast.warning {
      background: rgba(255, 170, 0, 0.12);
      border-color: #ffaa00;
      color: #ffaa00;
    }
    .cyber-toast.info {
      background: rgba(0, 123, 255, 0.12);
      border-color: #007bff;
      color: #007bff;
    }
    .toast-icon { font-size: 16px; }
    .toast-msg { flex: 1; }
    .toast-dismiss {
      background: none;
      border: none;
      color: inherit;
      cursor: pointer;
      font-size: 14px;
      opacity: 0.6;
    }
    .toast-dismiss:hover { opacity: 1; }
    @media (prefers-reduced-motion: reduce) { .cyber-toast { animation: none; } }
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
  `],
})
export class ToastComponent {
  toasts$: Observable<Toast[]>;

  constructor(private toastService: ToastService) {
    this.toasts$ = this.toastService.toasts;
  }

  dismiss(id: number) {
    this.toastService.dismiss(id);
  }
}



