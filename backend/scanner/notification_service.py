from __future__ import annotations

import logging
from typing import Optional

from .ai_module.chatbot import format_score
from .models import Notification
from .cve_data import collect_scan_cves
from .realtime_service import publish_event

logger = logging.getLogger(__name__)


def create_notification(scan, titre, message, type, niveau='info'):
    notification, created = Notification.objects.get_or_create(
        scan=scan, type=type, titre=titre,
        defaults={'message': message, 'niveau': niveau},
    )
    if not created and (notification.message != message or notification.niveau != niveau):
        notification.message = message
        notification.niveau = niveau
        notification.save(update_fields=['message', 'niveau'])
    if created:
        publish_event('notification.created', scan, {
            'notification_id': notification.id,
            'category': type,
            'severity': niveau,
        })
        logger.info(
            'notification_created notification_id=%s type=%s scan_id=%s',
            notification.id, type, scan.id,
        )
    return notification


def notify_scan_started(scan):
    return create_notification(
        scan,
        f'Scan démarré — {scan.domaine}',
        f'Le scan de sécurité sur {scan.domaine} vient de démarrer.',
        'scan_started',
        'info',
    )


def notify_scan_finished(scan):
    return create_notification(
        scan,
        f'Scan terminé — {scan.domaine}',
        f'Le scan de sécurité sur {scan.domaine} est terminé. '
        f'Score de risque IA : {format_score(scan.score_risque_ia)}/10.',
        'scan_finished',
        'success',
    )


def notify_scan_cancelled(scan):
    return create_notification(
        scan,
        f'Scan annulé — {scan.domaine}',
        f"Le scan de sécurité sur {scan.domaine} a été interrompu à la demande de l'utilisateur.",
        'scan_cancelled',
        'warning',
    )


def notify_scan_failed(scan, error=None):
    detail = str(error or scan.error_message or 'Erreur inconnue').strip()
    return create_notification(
        scan,
        f'Échec du scan — {scan.domaine}',
        f'Le scan de {scan.domaine} a échoué : {detail[:500]}',
        'scan_failed',
        'critical',
    )


def notify_report_ready(scan, format_rapport='PDF'):
    label = format_rapport.upper()
    return create_notification(
        scan,
        f'Rapport {label} disponible — {scan.domaine}',
        f'Le rapport {label} pour {scan.domaine} est prêt au téléchargement.',
        'report_ready',
        'success',
    )


def notify_report_failed(scan, error):
    return create_notification(
        scan,
        f'Échec de génération du rapport — {scan.domaine}',
        f"Le rapport de {scan.domaine} n'a pas pu être généré : {str(error)[:500]}",
        'report_failed',
        'critical',
    )


def notify_report_emailed(scan, recipients):
    recipient_text = ', '.join(recipients or []) or 'destinataire configuré'
    return create_notification(
        scan,
        f'Rapport envoyé par e-mail — {scan.domaine}',
        f'Le rapport de {scan.domaine} a été envoyé à {recipient_text}.',
        'report_emailed',
        'success',
    )


def notify_report_email_failed(scan, error):
    return create_notification(
        scan,
        f"Échec de l'envoi du rapport — {scan.domaine}",
        f"Le rapport de {scan.domaine} n'a pas pu être envoyé : {str(error)[:500]}",
        'email_failed',
        'warning',
    )


def notify_critical_cve(scan, cve):
    score = float(cve.get('cvss_score') or 0) if isinstance(cve, dict) else float(cve.cvss_score or 0)
    if score < 7:
        return None
    cve_id = cve.get('cve_id') if isinstance(cve, dict) else cve.cve_id
    description = cve.get('description') if isinstance(cve, dict) else cve.description
    niveau = 'critical' if score >= 9 else 'warning'
    return create_notification(
        scan,
        f'CVE critique détectée — {cve_id}',
        f'{cve_id} détectée sur {scan.domaine} (CVSS {format_score(score)}/10). {description[:300]}',
        'new_cve',
        niveau,
    )


def notify_high_risk(scan):
    if float(scan.score_risque_ia or 0) < 9:
        return None
    return create_notification(
        scan,
        f'Risque élevé — {scan.domaine}',
        f'Le score de risque IA ({format_score(scan.score_risque_ia)}/10) '
        f'dépasse le seuil critique sur {scan.domaine}.',
        'high_risk',
        'critical',
    )


def notify_scan_events(scan, cves: Optional[list] = None):
    notifications = [notify_scan_finished(scan)]
    high = notify_high_risk(scan)
    if high:
        notifications.append(high)
    results = scan.resultats_ssl if isinstance(scan.resultats_ssl, dict) else {}
    selected_cves = cves if cves is not None else collect_scan_cves(scan, results)
    for cve in selected_cves:
        notification = notify_critical_cve(scan, cve)
        if notification:
            notifications.append(notification)
    return notifications
