import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output } from '@angular/core';
import { ManualVulnerability, ScanView } from '../../../models/history.model';
import { VulnManuelleForm } from '../../vuln-manuelle-form/vuln-manuelle-form';
import { ReportActions } from '../report-actions/report-actions';
import { A11yModule } from '@angular/cdk/a11y';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'app-scan-detail-dialog', standalone: true, imports: [CommonModule, ReportActions, VulnManuelleForm, A11yModule], templateUrl: './scan-detail-dialog.html',
})
export class ScanDetailDialog {
  @Input({ required: true }) scan!: ScanView; @Input() vulnerabilities: ManualVulnerability[] = []; @Input() showForm = false;
  @Output() close = new EventEmitter<void>(); @Output() remove = new EventEmitter<Event>(); @Output() openForm = new EventEmitter<void>(); @Output() closeForm = new EventEmitter<void>(); @Output() added = new EventEmitter<void>(); @Output() removeVulnerability = new EventEmitter<number>();
  @Output() pdf = new EventEmitter<Event>(); @Output() email = new EventEmitter<Event>(); @Output() excel = new EventEmitter<Event>(); @Output() json = new EventEmitter<Event>();
}



