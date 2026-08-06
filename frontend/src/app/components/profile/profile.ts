import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './profile.html',
  styleUrl: './profile.scss',
})
export class Profile implements OnInit {
  user: any = null;

  showPasswordForm = false;
  oldPassword = '';
  newPassword = '';
  confirmPassword = '';
  message = '';
  error = '';
  loading = false;

  private apiUrl = `${environment.API_BASE_URL}/auth`;

  constructor(
    private authService: AuthService,
    private http: HttpClient,
    private router: Router,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit() {
    this.user = this.authService.getCurrentUser();
  }

  togglePasswordForm() {
    this.showPasswordForm = !this.showPasswordForm;
    this.message = '';
    this.error = '';
    this.oldPassword = '';
    this.newPassword = '';
    this.confirmPassword = '';
  }

  changePassword() {
    this.message = '';
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
          this.loading = false;
          this.message = res.message || 'Mot de passe modifié avec succès';
          this.oldPassword = '';
          this.newPassword = '';
          this.confirmPassword = '';
          this.cdr.detectChanges();
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

  roleLabel(role: string): string {
    const labels: any = {
      admin: 'Administrateur',
      analyst: 'Analyste Sécurité',
      viewer: 'Lecteur',
    };
    return labels[role] || role;
  }
}
