import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output } from '@angular/core';
import { ScanView } from '../../../models/history.model';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'app-report-actions', standalone: true, templateUrl: './report-actions.html',
})
export class ReportActions {
  @Input({ required: true }) scan!: ScanView;
  @Output() pdf = new EventEmitter<Event>(); @Output() email = new EventEmitter<Event>(); @Output() excel = new EventEmitter<Event>(); @Output() json = new EventEmitter<Event>();
  emit(output: EventEmitter<Event>, event: Event): void { event.stopPropagation(); output.emit(event); }
}


