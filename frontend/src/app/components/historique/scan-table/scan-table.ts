import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output } from '@angular/core';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatTableDataSource, MatTableModule } from '@angular/material/table';
import { ScanView } from '../../../models/history.model';
import { ReportActions } from '../report-actions/report-actions';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'app-scan-table', standalone: true, imports: [CommonModule, MatTableModule, MatPaginatorModule, ReportActions], templateUrl: './scan-table.html',
})
export class ScanTable {
  @Input({ required: true }) dataSource!: MatTableDataSource<ScanView>; @Input({ required: true }) displayedColumns: string[] = [];
  @Input() loading = false; @Input() total = 0; @Input() currentPage = 1; @Input() pageSize = 10;
  @Output() view = new EventEmitter<ScanView>(); @Output() remove = new EventEmitter<ScanAction>(); @Output() pdf = new EventEmitter<ScanAction>(); @Output() email = new EventEmitter<ScanAction>(); @Output() excel = new EventEmitter<ScanAction>(); @Output() json = new EventEmitter<ScanAction>(); @Output() page = new EventEmitter<PageEvent>();
  reportLabel(status: ScanView['rapportStatus']): string { return ({ non_genere: 'NON GÉNÉRÉ', generation: 'GÉNÉRATION...', pret: 'PRÊT', erreur: 'ERREUR' })[status]; }
  emailLabel(status: ScanView['emailStatus']): string { return ({ non_envoye: 'NON ENVOYÉ', envoi: 'ENVOI...', envoye: 'ENVOYÉ', erreur: 'ERREUR' })[status]; }
}
export interface ScanAction { scan: ScanView; event: Event; }


