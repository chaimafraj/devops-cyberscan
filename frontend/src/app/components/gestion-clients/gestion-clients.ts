import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ClientService, Client } from '../../services/client';

@Component({
  selector: 'app-gestion-clients',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './gestion-clients.html',
  styleUrl: './gestion-clients.scss',
})
export class GestionClients implements OnInit {
  clients: Client[] = [];
  currentPage = 1;
  totalPages = 1;
  totalCount = 0;
  pageSize = 10;

  loading = false;
  error = '';
  successMessage = '';

  // Formulaire ajout
  showAddForm = false;
  newNom = '';
  newEmail = '';
  addLoading = false;
  addError = '';

  constructor(
    private clientService: ClientService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit() {
    this.loadClients();
  }

  loadClients() {
    this.loading = true;
    this.error = '';
    this.clientService.getClients(this.currentPage, this.pageSize).subscribe({
      next: (res) => {
        this.clients = res.results;
        this.totalPages = res.total_pages;
        this.totalCount = res.count;
        this.currentPage = res.current_page;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.error = err.error?.error || 'Erreur lors du chargement des clients';
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  goToPage(page: number) {
    if (page < 1 || page > this.totalPages) return;
    this.currentPage = page;
    this.loadClients();
  }

  toggleAddForm() {
    this.showAddForm = !this.showAddForm;
    this.newNom = '';
    this.newEmail = '';
    this.addError = '';
    this.successMessage = '';
  }

  newUsername = '';

  createClient() {
    this.addError = '';
    this.error = '';
    this.successMessage = '';

    if (!this.newNom || !this.newUsername || !this.newEmail) {
      this.addError = "Nom, nom d'utilisateur et email requis";
      this.cdr.detectChanges();
      return;
    }

    this.addLoading = true;
    this.cdr.detectChanges();

    this.clientService.createClient(this.newNom, this.newUsername, this.newEmail).subscribe({
      next: (response) => {
        this.addLoading = false;
        const emailStatus = String(response?.email_status || '');

        if (!emailStatus.toLowerCase().startsWith('envoy')) {
          this.error = (
            `Client "${this.newNom}" créé, mais l'e-mail d'identifiants n'a pas été envoyé`
            + (emailStatus ? ` (${emailStatus})` : '')
            + '. Supprimez ce client avant de réessayer.'
          );
          this.newNom = '';
          this.newUsername = '';
          this.newEmail = '';
          this.showAddForm = false;
          this.currentPage = 1;
          this.loadClients();
          return;
        }

        this.successMessage = `Client "${this.newNom}" créé — email envoyé.`;
        this.newNom = '';
        this.newUsername = '';
        this.newEmail = '';
        this.showAddForm = false;
        this.currentPage = 1;
        this.loadClients();
      },
      error: (err) => {
        this.addLoading = false;
        this.addError = err.error?.error || 'Erreur lors de la création du client';
        this.cdr.detectChanges();
      },
    });
  }

  deleteClient(client: Client) {
    this.clientService.deleteClient(client.id).subscribe({
      next: () => {
        this.successMessage = `Client "${client.nom}" supprimé.`;
        this.loadClients();
      },
      error: (err) => {
        this.error = err.error?.error || 'Erreur lors de la suppression';
        this.cdr.detectChanges();
      },
    });
  }
}
