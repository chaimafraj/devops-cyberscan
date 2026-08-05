import { AfterViewInit, ChangeDetectionStrategy, Component, ElementRef, OnDestroy, ViewChild } from '@angular/core';

@Component({
  selector: 'app-matrix-background', standalone: true,
  templateUrl: './matrix-background.html', styleUrl: './matrix-background.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MatrixBackground implements AfterViewInit, OnDestroy {
  @ViewChild('canvas', { static: true }) private canvasRef!: ElementRef<HTMLCanvasElement>;
  private interval: ReturnType<typeof setInterval> | null = null;
  ngAfterViewInit(): void {
    if (navigator.userAgent.toLowerCase().includes('jsdom')) return;
    if (typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const canvas = this.canvasRef.nativeElement;
    const context = canvas.getContext('2d');
    if (!context) return;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const drops = Array<number>(Math.floor(canvas.width / 14)).fill(1);
    this.interval = setInterval(() => {
      context.fillStyle = 'rgba(0,0,0,0.05)';
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.fillStyle = '#00FF41';
      context.font = '13px monospace';
      drops.forEach((y, index) => {
        context.fillText(String.fromCharCode(0x30a0 + Math.random() * 96), index * 14, y * 14);
        if (y * 14 > canvas.height && Math.random() > 0.975) drops[index] = 0;
        drops[index]++;
      });
    }, 50);
  }
  ngOnDestroy(): void { if (this.interval) clearInterval(this.interval); }
}

