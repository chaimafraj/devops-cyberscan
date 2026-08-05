"""
Envoi d'emails post-scan avec le rapport PDF en pièce jointe.

Gère les erreurs d'envoi sans faire échouer le pipeline de scan.
"""
from __future__ import annotations

import logging
from io import BytesIO
from email.mime.image import MIMEImage
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Any, Dict, List, Optional

from django.conf import settings
from django.core import signing
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

from PIL import Image, ImageDraw, ImageFont
from reportlab.graphics.barcode.qr import QrCodeWidget

from .models import Rapport, Scan
from .report_generator import (
    build_report_context,
    risk_level_from_score,
    security_score_from_risk,
    resolve_pdf_absolute_path,
)

logger = logging.getLogger(__name__)

REPORT_DOWNLOAD_SALT = 'cyberscan.report-email-download'


def _with_query_parameter(url: str, name: str, value: object) -> str:
    parts = urlsplit(url)
    query = [(key, item) for key, item in parse_qsl(parts.query, keep_blank_values=True) if key != name]
    query.append((name, str(value)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _notify_email_status(scan, result):
    try:
        from .notification_service import notify_report_emailed, notify_report_email_failed
        if result.get('success'):
            notify_report_emailed(scan, result.get('recipients', []))
        else:
            notify_report_email_failed(scan, result.get('error') or 'Erreur envoi inconnue')
    except Exception:
        logger.warning('email_status_notification_failed scan_id=%s', scan.id, exc_info=True)


def resolve_recipient_emails(scan: Scan, extra_emails: Optional[List[str]] = None) -> List[str]:
    """
    Destinataires par ordre de priorité :
    1. emails explicites (ex. paramètre request)
    2. email du client lié au scan
    3. email de l'utilisateur qui a lancé le scan
    """
    recipients: List[str] = []
    seen = set()

    def add(addr: Optional[str]):
        if not addr:
            return
        email = str(addr).strip()
        if not email or '@' not in email:
            return
        key = email.lower()
        if key in seen:
            return
        seen.add(key)
        recipients.append(email)

    for e in extra_emails or []:
        add(e)

    if scan.client_id and getattr(scan, 'client', None) is not None:
        add(scan.client.email)
    elif scan.client_id:
        try:
            add(scan.client.email)
        except Exception:
            logger.warning('Email client inaccessible pour le scan %s', scan.id, exc_info=True)

    if scan.created_by_id and getattr(scan, 'created_by', None) is not None:
        add(scan.created_by.email)
    elif scan.created_by_id:
        try:
            add(scan.created_by.email)
        except Exception:
            logger.warning('Email createur inaccessible pour le scan %s', scan.id, exc_info=True)

    return recipients


def build_report_url(scan: Scan) -> str:
    site_url = getattr(settings, 'CYBERSCAN_SITE_URL', 'http://localhost:4200').rstrip('/')
    history_url = getattr(
        settings,
        'CYBERSCAN_HISTORY_URL',
        f'{site_url}/historique',
    )
    return _with_query_parameter(history_url, 'scan', scan.id)


def build_api_report_url(scan: Scan) -> str:
    api_base = getattr(settings, 'CYBERSCAN_API_URL', 'http://localhost:8000').rstrip('/')
    token = signing.dumps({'scan_id': scan.id}, salt=REPORT_DOWNLOAD_SALT)
    base_url = f'{api_base}/api/scans/{scan.id}/rapport/email-download/'
    return _with_query_parameter(base_url, 'token', token)


def _item_value(item: object, *names: str):
    for name in names:
        if isinstance(item, dict) and item.get(name) is not None:
            return item.get(name)
        value = getattr(item, name, None)
        if value is not None:
            return value
    return None


def _severity_bucket(item: object, default: str = 'low') -> str:
    severity = str(_item_value(item, 'severity', 'risk', 'baseSeverity', 'severite') or '').lower()
    if 'critical' in severity or 'critique' in severity:
        return 'critical'
    if 'high' in severity or 'eleve' in severity or 'élevé' in severity:
        return 'high'
    if 'medium' in severity or 'moyen' in severity or 'modere' in severity:
        return 'medium'
    if 'low' in severity or 'faible' in severity:
        return 'low'
    try:
        score = float(_item_value(item, 'cvss_score', 'cvssScore', 'score') or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= 9:
        return 'critical'
    if score >= 7:
        return 'high'
    if score >= 4:
        return 'medium'
    return default


def build_email_metrics(scan: Scan, context: Optional[dict] = None) -> Dict[str, Any]:
    ctx = context or build_report_context(scan)
    findings: List[tuple[object, str]] = []
    findings.extend((item, 'low') for item in (ctx.get('cves') or []))
    findings.extend((item, 'medium') for item in (ctx.get('zap_findings') or []))
    for item in ctx.get('vulnerabilities') or []:
        default = 'high' if str(item).upper() in ('TLSV1.0', 'TLSV1.1', 'WEAK_CIPHER') else 'medium'
        findings.append((item, default))

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for item, default in findings:
        counts[_severity_bucket(item, default)] += 1

    vulnerabilities = {str(item).upper() for item in (ctx.get('vulnerabilities') or [])}
    protocols = ctx.get('protocols') or []
    ssl_labs = ctx.get('ssllabs') or {}
    ssl_status = 'Non évalué'
    if vulnerabilities.intersection({'TLSV1.0', 'TLSV1.1', 'WEAK_CIPHER'}):
        ssl_status = 'À renforcer'
    elif any(str(_item_value(item, 'status') or '').lower() in ('obsolete', 'vulnerable') for item in protocols):
        ssl_status = 'À renforcer'
    elif isinstance(ssl_labs, dict) and (ssl_labs.get('grade') or ssl_labs.get('status')):
        grade = str(ssl_labs.get('grade') or '').upper()
        ssl_status = 'Valide' if grade in ('A', 'A+', 'A-') else 'À vérifier'
    elif protocols or ctx.get('sslscan') or ctx.get('openssl'):
        ssl_status = 'Valide'

    return {
        'total': sum(counts.values()),
        **counts,
        'ssl_status': ssl_status,
    }


def _display_score(value: object) -> str:
    try:
        number = round(float(value), 1)
    except (TypeError, ValueError):
        number = 0.0
    return str(int(number)) if number.is_integer() else f'{number:.1f}'


def _risk_color(label: object) -> str:
    key = str(label).lower()
    if 'criti' in key:
        return '#dc2626'
    if 'élev' in key or 'elev' in key:
        return '#ea580c'
    if 'moy' in key:
        return '#d97706'
    return '#15803d'


def _build_email_summary(domain: str, risk: str, security_score: str, metrics: dict) -> str:
    return (
        f"L'analyse du domaine {domain} indique un niveau de risque {risk} "
        f"avec un score de sécurité de {security_score}/10. "
        f"{metrics['total']} vulnérabilité(s) ont été détectées, dont "
        f"{metrics['critical']} critique(s), {metrics['high']} élevée(s), "
        f"{metrics['medium']} moyenne(s) et {metrics['low']} faible(s). "
        f"Le certificat SSL est {metrics['ssl_status'].lower()}. Consultez le rapport complet "
        f"pour connaître les résultats détaillés et les recommandations de sécurité."
    )


def build_email_context(scan: Scan, context: Optional[dict] = None) -> Dict[str, Any]:
    ctx = context or build_report_context(scan)
    risk_label = ctx.get('niveau_risque') or risk_level_from_score(scan.score_risque_ia)[0]
    security_score = ctx.get('score_global_securite')
    if security_score is None:
        security_score = security_score_from_risk(scan.score_risque_ia)
    security_display = _display_score(security_score)
    metrics = build_email_metrics(scan, ctx)
    return {
        'domaine': scan.domaine,
        'date_scan': scan.date_scan.strftime('%d/%m/%Y à %H:%M UTC') if scan.date_scan else '—',
        'niveau_risque': risk_label,
        'score_securite': security_display,
        'score_ia': _display_score(scan.score_risque_ia),
        'metrics': metrics,
        'statut_ssl': metrics['ssl_status'],
        'resume_executif': _build_email_summary(
            scan.domaine, risk_label, security_display, metrics,
        ),
        'url_front': build_report_url(scan),
        'url_pdf': build_api_report_url(scan),
        'risk_color': _risk_color(risk_label),
        'logo_cid': 'cyberscan-logo',
        'qr_cid': 'cyberscan-report-qr',
    }


def _load_font(size: int, bold: bool = False):
    names = ('DejaVuSans-Bold.ttf', 'arialbd.ttf') if bold else ('DejaVuSans.ttf', 'arial.ttf')
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def build_logo_png() -> bytes:
    image = Image.new('RGBA', (320, 72), (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((4, 6, 62, 64), radius=14, fill='#0B1F33', outline='#22C55E', width=3)
    draw.text((15, 20), 'CS', font=_load_font(22, bold=True), fill='#FFFFFF')
    draw.text((76, 8), 'CyberScan', font=_load_font(30, bold=True), fill='#FFFFFF')
    draw.text((78, 45), 'SECURITY AUDIT PLATFORM', font=_load_font(10, bold=True), fill='#93C5FD')
    output = BytesIO()
    image.save(output, format='PNG', optimize=True)
    return output.getvalue()


def build_qr_png(url: str, size: int = 220) -> bytes:
    widget = QrCodeWidget(url)
    widget.qr.make()
    matrix = widget.qr.modules
    border = 4
    modules = len(matrix) + border * 2
    scale = max(1, size // modules)
    image_size = modules * scale
    image = Image.new('RGB', (image_size, image_size), '#FFFFFF')
    draw = ImageDraw.Draw(image)
    for row, values in enumerate(matrix):
        for column, enabled in enumerate(values):
            if enabled:
                x = (column + border) * scale
                y = (row + border) * scale
                draw.rectangle((x, y, x + scale - 1, y + scale - 1), fill='#0B1F33')
    output = BytesIO()
    image.save(output, format='PNG', optimize=True)
    return output.getvalue()


def _inline_png(content: bytes, cid: str, filename: str) -> MIMEImage:
    image = MIMEImage(content, _subtype='png')
    image.add_header('Content-ID', f'<{cid}>')
    image.add_header('Content-Disposition', 'inline', filename=filename)
    return image


def build_email_subject(scan: Scan, context: Optional[dict] = None) -> str:
    return f"[CyberScan] Rapport d'audit de sécurité disponible — {scan.domaine}"


def build_email_body(scan: Scan, context: Optional[dict] = None) -> str:
    email_ctx = build_email_context(scan, context)
    metrics = email_ctx['metrics']
    return (
        f"CyberScan — Rapport d'audit de sécurité disponible\n"
        f"Domaine : {email_ctx['domaine']}\n\n"
        f"Bonjour,\n\n"
        f"Votre audit de sécurité du domaine {email_ctx['domaine']} a été réalisé avec succès. "
        f"Le rapport est disponible et joint à cet e-mail au format PDF.\n\n"
        f"RÉSUMÉ DU SCAN\n"
        f"Domaine : {email_ctx['domaine']}\n"
        f"Date du scan : {email_ctx['date_scan']}\n"
        f"Niveau de risque : {email_ctx['niveau_risque']}\n"
        f"Score de sécurité : {email_ctx['score_securite']}/10\n"
        f"Score IA : {email_ctx['score_ia']}/10\n"
        f"Vulnérabilités : {metrics['total']}\n\n"
        f"RÉSUMÉ EXÉCUTIF\n{email_ctx['resume_executif']}\n\n"
        f"Consulter le rapport : {email_ctx['url_front']}\n"
        f"Télécharger le PDF : {email_ctx['url_pdf']}\n\n"
        f"Le rapport est également disponible aux formats PDF, Excel et JSON depuis votre tableau de bord CyberScan.\n\n"
        f"Nous vous remercions de votre confiance.\n\nCordialement,\nL'équipe CyberScan\n\n"
        f"Cet e-mail a été généré automatiquement par la plateforme CyberScan. Merci de ne pas répondre à ce message."
    )


def build_email_html(scan: Scan, context: Optional[dict] = None) -> str:
    return render_to_string('scanner/emails/scan_report.html', build_email_context(scan, context))


def send_scan_report_email(
    scan: Scan,
    rapport: Optional[Rapport] = None,
    extra_emails: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Envoie l'email de rapport avec PDF en pièce jointe.

    Retourne un dict :
      {
        'success': bool,
        'recipients': [...],
        'error': str|None,
        'skipped': bool,   # True si aucun destinataire
      }

    Les erreurs sont capturées et loggées : elles ne remontent pas d'exception
    non gérée vers l'appelant (sauf si on souhaite propager — ici non).
    """
    result: Dict[str, Any] = {
        'success': False,
        'recipients': [],
        'error': None,
        'skipped': False,
    }

    try:
        recipients = resolve_recipient_emails(scan, extra_emails=extra_emails)
        result['recipients'] = recipients

        if not recipients:
            result['skipped'] = True
            result['error'] = 'Aucun destinataire email disponible pour ce scan'
            logger.warning(
                'Email rapport scan #%s non envoyé : aucun destinataire (domaine=%s)',
                scan.id, scan.domaine,
            )
            _notify_email_status(scan, result)
            return result

        if rapport is None:
            rapport = scan.rapports.order_by('-date_generation').first()

        context = build_report_context(scan)
        subject = build_email_subject(scan, context)
        body = build_email_body(scan, context)
        html_body = build_email_html(scan, context)
        email_context = build_email_context(scan, context)

        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or settings.EMAIL_HOST_USER
        email = EmailMultiAlternatives(
            subject=subject,
            body=body,
            from_email=from_email,
            to=recipients,
        )
        email.attach_alternative(html_body, 'text/html')
        email.mixed_subtype = 'related'
        email.attach(_inline_png(build_logo_png(), email_context['logo_cid'], 'cyberscan-logo.png'))
        email.attach(
            _inline_png(
                build_qr_png(email_context['url_front']),
                email_context['qr_cid'],
                f"cyberscan-rapport-{scan.id}-qr.png",
            )
        )

        # Pièce jointe PDF
        if rapport is not None:
            pdf_path = resolve_pdf_absolute_path(rapport)
            if pdf_path.is_file():
                email.attach_file(str(pdf_path), mimetype='application/pdf')
            else:
                logger.error(
                    'PDF introuvable pour scan #%s (chemin=%s) — email sans pièce jointe',
                    scan.id, rapport.chemin_pdf,
                )
                # On envoie quand même le corps textuel
        else:
            logger.warning('Aucun Rapport PDF pour scan #%s — email sans pièce jointe', scan.id)

        email.send(fail_silently=False)
        result['success'] = True
        logger.info(
            'Email rapport scan #%s envoyé à %s',
            scan.id, ', '.join(recipients),
        )
        _notify_email_status(scan, result)
        return result

    except Exception as exc:
        # Gestion des erreurs d'envoi (SMTP, auth, réseau, etc.)
        error_msg = str(exc).strip() or exc.__class__.__name__
        result['success'] = False
        result['error'] = error_msg
        logger.exception(
            'Échec envoi email rapport scan #%s : %s',
            getattr(scan, 'id', '?'), error_msg,
        )
        _notify_email_status(scan, result)
        return result
