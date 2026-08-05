import logging

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from .models import Scan
from .realtime_service import publish_event, publish_on_commit
from .scan_cancellation import ScanCancellationCheck, ScanCancelled
from .scan_persistence import build_stored_results, replace_scan_cves

logger = logging.getLogger(__name__)


def _run_pipeline(target, is_prod, has_money, options, cancel_check=None):
    from .views import scan_single_site
    return scan_single_site(
        target,
        is_prod=is_prod,
        has_money=has_money,
        options=options,
        cancel_check=cancel_check,
    )


def _notify_safely(callback_name, scan, *args):
    try:
        from . import notification_service
        getattr(notification_service, callback_name)(scan, *args)
    except Exception:
        logger.exception('%s_failed scan_id=%s', callback_name, scan.id)


@shared_task(bind=True, name='scanner.execute_scan')
def execute_scan(self, scan_id, is_prod=True, has_money=False, options=None, email_to=None):
    options = options or {}
    task_id = self.request.id or ''
    updated = Scan.objects.filter(pk=scan_id, status=Scan.Status.PENDING).update(
        status=Scan.Status.RUNNING,
        started_at=timezone.now(),
        error_message='',
        celery_task_id=task_id,
    )
    if not updated:
        scan = Scan.objects.filter(pk=scan_id).first()
        if scan is None:
            raise Scan.DoesNotExist(f'Scan {scan_id} introuvable')
        if scan.status == Scan.Status.CANCELLED:
            return {'scan_id': scan.id, 'status': Scan.Status.CANCELLED}
        logger.warning('scan_task_ignored scan_id=%s status=%s', scan_id, scan.status)
        return {'scan_id': scan.id, 'status': scan.status}

    scan = Scan.objects.get(pk=scan_id)
    publish_event('scan.running', scan, {'status': Scan.Status.RUNNING})
    _notify_safely('notify_scan_started', scan)
    cancel_check = ScanCancellationCheck(scan_id)

    try:
        cancel_check.ensure_not_cancelled(force=True)
        result = _run_pipeline(
            scan.domaine,
            is_prod,
            has_money,
            options,
            cancel_check=cancel_check,
        )
        cancel_check.ensure_not_cancelled(force=True)
        if not result.get('success'):
            raise RuntimeError(result.get('error') or 'Le scan a échoué')

        completed_at = timezone.now()
        with transaction.atomic():
            scan = Scan.objects.select_for_update().get(pk=scan_id)
            if scan.status == Scan.Status.CANCELLED:
                raise ScanCancelled(f'Scan {scan_id} annulé')
            scan.resultats_ssl = build_stored_results(result)
            scan.score_risque_ia = round(float(result.get('score_risque_ia') or 0), 1)
            scan.status = Scan.Status.COMPLETED
            scan.completed_at = completed_at
            scan.error_message = ''
            scan.save(update_fields=[
                'resultats_ssl', 'score_risque_ia', 'status', 'completed_at', 'error_message',
            ])
            replace_scan_cves(scan, result.get('cves', []))
            publish_on_commit('scan.completed', scan, {
                'status': Scan.Status.COMPLETED,
                'score_risque_ia': scan.score_risque_ia,
            })

        _notify_safely('notify_scan_events', scan)

        try:
            from .report_pipeline import finalize_scan_report
            report = finalize_scan_report(scan, extra_emails=[email_to] if email_to else None)
            stored = dict(scan.resultats_ssl)
            stored['report'] = report
            Scan.objects.filter(pk=scan_id).update(resultats_ssl=stored)
        except Exception:
            logger.exception('scan_report_pipeline_failed scan_id=%s', scan_id)

        logger.info('scan_completed scan_id=%s duration_status=completed', scan_id)
        return {'scan_id': scan.id, 'status': Scan.Status.COMPLETED}
    except ScanCancelled:
        status_changed = Scan.objects.filter(
            pk=scan_id,
            status__in=[Scan.Status.PENDING, Scan.Status.RUNNING],
        ).update(
            status=Scan.Status.CANCELLED,
            error_message="Scan annulé par l'utilisateur.",
            completed_at=timezone.now(),
        )
        cancelled_scan = Scan.objects.get(pk=scan_id)
        if status_changed:
            publish_event('scan.cancelled', cancelled_scan, {'status': Scan.Status.CANCELLED})
        _notify_safely('notify_scan_cancelled', cancelled_scan)
        logger.info('scan_cancelled scan_id=%s', scan_id)
        return {'scan_id': scan_id, 'status': Scan.Status.CANCELLED}
    except Exception as exc:
        logger.exception('scan_task_failed scan_id=%s error_type=%s', scan_id, exc.__class__.__name__)
        updated = Scan.objects.filter(pk=scan_id).exclude(status=Scan.Status.CANCELLED).update(
            status=Scan.Status.FAILED,
            error_message=str(exc)[:1000],
            completed_at=timezone.now(),
        )
        failed_scan = Scan.objects.filter(pk=scan_id).first()
        if failed_scan and failed_scan.status == Scan.Status.CANCELLED:
            return {'scan_id': scan_id, 'status': Scan.Status.CANCELLED}
        if updated and failed_scan:
            publish_event('scan.failed', failed_scan, {'status': Scan.Status.FAILED})
            _notify_safely('notify_scan_failed', failed_scan, exc)
        raise
