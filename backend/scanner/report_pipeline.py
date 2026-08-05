"""Point unique post-scan : génération PDF puis envoi par e-mail."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .models import Scan

logger = logging.getLogger(__name__)


def finalize_scan_report(
    scan: Scan,
    extra_emails: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Génère le PDF et envoie le rapport sans faire échouer le scan terminé."""
    outcome: Dict[str, Any] = {
        'rapport_id': None,
        'pdf_ok': False,
        'email': None,
        'errors': [],
    }

    rapport = None
    try:
        from .report_generator import generate_pdf_for_scan
        rapport = generate_pdf_for_scan(scan)
        outcome['rapport_id'] = rapport.id
        outcome['pdf_ok'] = True
    except Exception as exc:
        msg = f'PDF: {exc}'
        outcome['errors'].append(msg)
        logger.exception('finalize_scan_report PDF échoué scan #%s', scan.id)
        try:
            from .notification_service import notify_report_failed
            notify_report_failed(scan, exc)
        except Exception:
            logger.warning('report_failure_notification_failed scan_id=%s', scan.id, exc_info=True)

    try:
        from .report_email import send_scan_report_email
        email_result = send_scan_report_email(
            scan, rapport=rapport, extra_emails=extra_emails,
        )
        outcome['email'] = email_result
        if not email_result.get('success') and not email_result.get('skipped'):
            outcome['errors'].append(f"Email: {email_result.get('error')}")
    except Exception as exc:
        msg = f'Email: {exc}'
        outcome['errors'].append(msg)
        logger.exception('finalize_scan_report email échoué scan #%s', scan.id)
        try:
            from .notification_service import notify_report_email_failed
            notify_report_email_failed(scan, exc)
        except Exception:
            logger.warning('email_failure_notification_failed scan_id=%s', scan.id, exc_info=True)

    return outcome
