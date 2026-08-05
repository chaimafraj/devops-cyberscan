import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface Toast {
  id: number;
  type: 'success' | 'error' | 'info' | 'warning';
  message: string;
}

@Injectable({ providedIn: 'root' })
export class ToastService {
  private toasts$ = new BehaviorSubject<Toast[]>([]);
  private counter = 0;

  get toasts() {
    return this.toasts$.asObservable();
  }

  show(type: Toast['type'], message: string, durationMs = 5000) {
    const id = ++this.counter;
    const toast: Toast = { id, type, message };
    this.toasts$.next([...this.toasts$.value, toast]);
    setTimeout(() => this.dismiss(id), durationMs);
  }

  success(message: string) {
    this.show('success', message);
  }

  error(message: string) {
    this.show('error', message);
  }

  info(message: string) {
    this.show('info', message);
  }

  warning(message: string) {
    this.show('warning', message);
  }

  dismiss(id: number) {
    this.toasts$.next(this.toasts$.value.filter((t) => t.id !== id));
  }
}
