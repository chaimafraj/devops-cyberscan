import { Component, Input, Output, EventEmitter, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScannerService } from '../../services/scanner.service';

@Component({
  selector: 'app-vuln-manuelle-form',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './vuln-manuelle-form.html',
  styleUrl: './vuln-manuelle-form.scss',
})
export class VulnManuelleForm implements OnInit {
  @Input() scanId!: number;
  @Output() close = new EventEmitter<void>();
  @Output() added = new EventEmitter<void>();

  templates: any = {};
  loading = false;
  error = '';

  types = [
    { value: 'idor', label: 'IDOR - Insecure Direct Object Reference' },
    { value: 'lfi', label: 'LFI - Local File Inclusion' },
    { value: 'xss', label: 'XSS - Cross-Site Scripting' },
    { value: 'sqli', label: 'SQL Injection' },
    { value: 'csrf', label: 'CSRF' },
    { value: 'broken_auth', label: 'Broken Authentication' },
    { value: 'sensitive_data', label: 'Sensitive Data Exposure' },
    { value: 'spam', label: 'Spam / Abus' },
    { value: 'autre', label: 'Autre' },
  ];

  risks = [
    { value: 'critical', label: 'Critique' },
    { value: 'high', label: 'Élevé' },
    { value: 'medium', label: 'Moyen' },
    { value: 'low', label: 'Faible' },
  ];

  form = {
    type_vuln: 'idor',
    nom: '',
    impacted_element: '',
    description: '',
    risk: 'high',
    cvss_score: 0,
    cvss_vector: '',
    priorite: 'Important',
    complexite: 'Faible',
    technical_business_risks: '',
    recommandation: '',
    proof_of_concept: '',
    references: '',
  };

  constructor(
    private scannerService: ScannerService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit() {
    this.scannerService.getVulnTemplates().subscribe({
      next: (data) => {
        this.templates = data;
        this.applyTemplate();
      },
    });
  }

  applyTemplate() {
    const tpl = this.templates[this.form.type_vuln];
    if (tpl) {
      this.form.description = tpl.description || '';
      this.form.technical_business_risks = tpl.technical_business_risks || '';
      this.form.recommandation = tpl.recommandation || '';
    }
  }

  onTypeChange() {
    this.applyTemplate();
    this.cdr.detectChanges();
  }

  submit() {
    this.error = '';

    if (!this.form.nom) {
      this.error = 'Le nom de la vulnérabilité est requis';
      this.cdr.detectChanges();
      return;
    }

    this.loading = true;
    this.cdr.detectChanges();

    this.scannerService.addVulnManuelle(this.scanId, this.form).subscribe({
      next: () => {
        this.loading = false;
        this.added.emit();
        this.close.emit();
      },
      error: (err) => {
        this.loading = false;
        this.error = err.error?.error || 'Erreur lors de l’ajout';
        this.cdr.detectChanges();
      },
    });
  }

  cancel() {
    this.close.emit();
  }
}
