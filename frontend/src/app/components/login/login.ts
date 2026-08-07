import { Component, OnInit, OnDestroy, ViewEncapsulation } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  imports: [FormsModule, CommonModule],
  templateUrl: './login.html',
  styleUrl: './login.scss',
  standalone: true,
  encapsulation: ViewEncapsulation.None,
})
export class Login implements OnInit, OnDestroy {
  username = '';
  password = '';
  loading = false;
  errorMsg = '';
  private matrixInterval: any;

  constructor(
    private authService: AuthService,
    private router: Router,
  ) {}

  ngOnInit() {
    if (this.authService.isLoggedIn()) {
      const user = this.authService.getCurrentUser();
      if (user?.must_change_password) {
        this.router.navigate(['/force-password']);
      } else {
        this.router.navigate(['/dashboard']);
      }
    }
    this.startMatrix();
  }

  ngOnDestroy() {
    if (this.matrixInterval) clearInterval(this.matrixInterval);
  }

  login() {
    if (!this.username || !this.password) {
      this.errorMsg = 'Veuillez remplir tous les champs.';
      return;
    }
    this.loading = true;
    this.errorMsg = '';

    this.authService.login(this.username, this.password).subscribe({
      next: (response: any) => {
        this.loading = false;
        if (response.user?.must_change_password) {
          this.router.navigate(['/force-password']);
        } else {
          this.router.navigate(['/dashboard']);
        }
      },
      error: (err) => {
        this.loading = false;
        this.errorMsg = err.error?.error || 'Identifiants incorrects.';
      },
    });
  }

  startMatrix() {
    setTimeout(() => {
      const canvas = document.getElementById('login-matrix') as HTMLCanvasElement;
      if (!canvas) return;
      const ctx = canvas.getContext('2d')!;
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const cols = Math.floor(canvas.width / 14);
      const drops = Array(cols).fill(1);
      this.matrixInterval = setInterval(() => {
        ctx.fillStyle = 'rgba(0,0,0,0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00FF41';
        ctx.font = '13px monospace';
        drops.forEach((y, i) => {
          const ch = String.fromCharCode(0x30a0 + Math.random() * 96);
          ctx.fillText(ch, i * 14, y * 14);
          if (y * 14 > canvas.height && Math.random() > 0.975) drops[i] = 0;
          drops[i]++;
        });
      }, 50);
    }, 100);
  }
}
