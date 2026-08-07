import { Component, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-force-password',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './force-password.html',
  styleUrl: './force-password.scss',
})
export class ForcePassword {
  oldPassword = '';
  newPassword = '';
  confirmPassword = '';
  error = '';
  loading = false;

  private apiUrl = `${environment.API_BASE_URL}/auth`;

  constructor(
    private http: HttpClient,
    private authService: AuthService,
    private router: Router,
    private cdr: ChangeDetectorRef,
  ) {}

  submit() {
    this.error = '';

    if (!this.oldPassword || !this.newPassword || !this.confirmPassword) {
      this.error = 'Tous les champs sont requis';
      this.cdr.detectChanges();
      return;
    }

    if (this.newPassword !== this.confirmPassword) {
      this.error = 'Les mots de passe ne correspondent pas';
      this.cdr.detectChanges();
      return;
    }

    if (this.newPassword.length < 6) {
      this.error = 'Le mot de passe doit contenir au moins 6 caractères';
      this.cdr.detectChanges();
      return;
    }

    this.loading = true;
    this.cdr.detectChanges();

    this.http
      .post(`${this.apiUrl}/change-password/`, {
        old_password: this.oldPassword,
        new_password: this.newPassword,
      })
      .subscribe({
        next: (res: any) => {
          this.authService.updateCurrentUser({
            ...(res?.user || {}),
            must_change_password: false,
          });
          this.loading = false;
          this.cdr.detectChanges();
          this.router.navigateByUrl('/dashboard');
        },
        error: (err) => {
          this.loading = false;
          this.error = err.error?.error || 'Erreur lors du changement de mot de passe';
          this.cdr.detectChanges();
        },
      });
  }

  logout() {
    this.authService.logout();
  }
}
