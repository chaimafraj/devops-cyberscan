import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-auth',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './auth.html',
  styleUrl: './auth.scss',
})
export class Auth {
  // Note: Ken el error mta3 switchMode mezel, baddel esm el class l "AuthComponent"
  isLoginMode: boolean = true;

  // Form Models mta3 el inputs [(ngModel)]
  username: string = '';
  email: string = '';
  password: string = '';
  selectedRole: string = 'User';

  message: string = '';
  isError: boolean = false;

  constructor(
    private authService: AuthService,
    private router: Router,
  ) {}

  switchMode() {
    this.isLoginMode = !this.isLoginMode;
    this.message = '';
    this.isError = false;
  }

  onSubmit() {
    this.message = '';

    if (this.isLoginMode) {
      this.authService.login(this.username, this.password).subscribe({
        next: () => {
          this.isError = false;

          this.router.navigate(['/dashboard']).then(() => {
            console.log('Navigation au dashboard CYBERSCAN réussie.');
          });
        },
        error: (err) => {
          this.isError = true;
          this.message = err.error?.error || "Nom d'utilisateur ou mot de passe incorrect.";
        },
      });
    } else {
      const payload = {
        username: this.username,
        email: this.email,
        password: this.password,
        role: this.selectedRole,
      };

      this.authService.register(payload).subscribe({
        next: (res) => {
          this.isError = false;
          this.message = res.message || 'Compte créé avec succès ! Connectez-vous.';
          this.isLoginMode = true; // Raddou lil login form automatic
          // Reset lines
          this.password = '';
        },
        error: (err) => {
          this.isError = true;
          this.message = err.error?.error || "Erreur lors de l'inscription.";
        },
      });
    }
  }
}
