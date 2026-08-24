import { AfterViewInit, ChangeDetectionStrategy, Component, ElementRef, OnDestroy, ViewChild } from '@angular/core';

@Component({
  selector: 'app-matrix-background', standalone: true,
  templateUrl: './matrix-background.html', styleUrl: './matrix-background.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MatrixBackground implements AfterViewInit, OnDestroy {
  @ViewChild('canvas', { static: true }) private canvasRef!: ElementRef<HTMLCanvasElement>;
  private interval: ReturnType<typeof setInterval> | null = null;
  private resizeListener: (() => void) | null = null;
  private themeObserver: MutationObserver | null = null;
  ngAfterViewInit(): void {
    if (navigator.userAgent.toLowerCase().includes('jsdom')) return;
    if (typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    this.themeObserver = new MutationObserver(() => this.syncTheme());
    this.themeObserver.observe(document.body, { attributes: true, attributeFilter: ['data-theme'] });
    this.syncTheme();
  }

  ngOnDestroy(): void {
    this.stopMatrix();
    this.themeObserver?.disconnect();
  }

  private syncTheme(): void {
    if (document.body.getAttribute('data-theme') === 'light') {
      this.startMatrix();
      return;
    }
    this.stopMatrix();
  }

  private startMatrix(): void {
    if (this.interval) return;
    const canvas = this.canvasRef.nativeElement;
    const context = canvas.getContext('2d');
    if (!context) return;

    let drops: number[] = [];
    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      drops = Array<number>(Math.ceil(canvas.width / 14)).fill(1);
    };

    resizeCanvas();
    this.resizeListener = resizeCanvas;
    window.addEventListener('resize', resizeCanvas);

    this.interval = setInterval(() => {
      const styles = getComputedStyle(document.body);
      context.fillStyle = styles.getPropertyValue('--matrix-fade').trim();
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.fillStyle = styles.getPropertyValue('--matrix-glyph').trim();
      context.font = '13px monospace';
      drops.forEach((y, index) => {
        context.fillText(String.fromCharCode(0x30a0 + Math.random() * 96), index * 14, y * 14);
        if (y * 14 > canvas.height && Math.random() > 0.975) drops[index] = 0;
        drops[index]++;
      });
    }, 50);
  }

  private stopMatrix(): void {
    if (!this.interval) return;
    clearInterval(this.interval);
    this.interval = null;
    if (this.resizeListener) {
      window.removeEventListener('resize', this.resizeListener);
      this.resizeListener = null;
    }
    const canvas = this.canvasRef.nativeElement;
    const context = canvas.getContext('2d');
    context?.clearRect(0, 0, canvas.width, canvas.height);
  }
}

