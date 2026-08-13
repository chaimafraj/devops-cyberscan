import { DOCUMENT } from '@angular/common';
import { Inject, Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export type AppTheme = 'dark' | 'light';

@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly storageKey = 'theme';
  private readonly themeSubject = new BehaviorSubject<AppTheme>('dark');
  readonly theme$ = this.themeSubject.asObservable();

  constructor(@Inject(DOCUMENT) private readonly document: Document) {}

  initialize(): AppTheme {
    const stored = sessionStorage.getItem(this.storageKey);
    const theme: AppTheme = stored === 'light' || stored === 'dark' ? stored : 'dark';
    this.apply(theme);
    return theme;
  }

  get current(): AppTheme { return this.themeSubject.value; }
  toggle(): AppTheme { const next: AppTheme = this.current === 'dark' ? 'light' : 'dark'; this.apply(next); return next; }
  set(theme: AppTheme): void { this.apply(theme); }

  private apply(theme: AppTheme): void {
    sessionStorage.setItem(this.storageKey, theme);
    this.document.body.setAttribute('data-theme', theme);
    this.document.documentElement.setAttribute('data-theme', theme);
    this.document.documentElement.style.colorScheme = theme;
    this.themeSubject.next(theme);
  }
}
