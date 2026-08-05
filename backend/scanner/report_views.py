"""
API REST pour consulter et télécharger les rapports PDF CyberScan.
"""
from __future__ import annotations

import io
import logging
from pathlib import Path

from django.conf import settings
from django.core import signing
from django.http import FileResponse, Http404, HttpResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import Client, Rapport, Scan
from .access import user_can_access_scan
from .report_generator import (
    build_report_context,
    build_json_export,
    generate_pdf_for_scan,
    resolve_pdf_absolute_path,
)
from .report_excel import generate_excel_bytes, excel_filename_for_scan

logger = logging.getLogger(__name__)


def _user_can_access_scan(user, scan: Scan) -> bool:
    return user_can_access_scan(user, scan)

def _get_scan_or_error(request, pk):
    try:
        scan = Scan.objects.get(pk=pk)
    except Scan.DoesNotExist:
        return None, Response({'error': 'Scan introuvable'}, status=status.HTTP_404_NOT_FOUND)

    if not _user_can_access_scan(request.user, scan):
        return None, Response({'error': 'Accès refusé'}, status=status.HTTP_403_FORBIDDEN)

    return scan, None


def _latest_rapport(scan: Scan) -> Rapport | None:
    return scan.rapports.order_by('-date_generation').first()


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_rapport_detail(request, pk):
    """
    Consulter les métadonnées et le contenu structuré du rapport.

    GET /api/scans/<pk>/rapport/
    """
    scan, err = _get_scan_or_error(request, pk)
    if err:
        return err

    force_regenerate = request.query_params.get('force_regenerate', '').lower() in ('1', 'true', 'yes')
    rapport = None if force_regenerate else _latest_rapport(scan)
    # Génération à la demande si le signal a échoué ou scan antérieur
    if rapport is None:
        try:
            rapport = generate_pdf_for_scan(scan, force_regenerate=force_regenerate)
        except Exception as exc:
            logger.exception('Génération à la demande échouée pour scan #%s', scan.id)
            return Response(
                {
                    'error': f'Impossible de générer le rapport PDF: {exc}',
                    'scan_id': scan.id,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    context = build_report_context(scan)
    pdf_path = resolve_pdf_absolute_path(rapport)
    pdf_exists = pdf_path.is_file()

    return Response({
        'rapport': {
            'id': rapport.id,
            'scan_id': scan.id,
            'chemin_pdf': rapport.chemin_pdf,
            'date_generation': rapport.date_generation,
            'pdf_disponible': pdf_exists,
            'download_url': f'/api/scans/{scan.id}/rapport/download/',
        },
        'contenu': context,
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def scan_rapport_regenerate(request, pk):
    """Régénère explicitement le PDF, indépendamment de l'endpoint du chatbot."""
    scan, err = _get_scan_or_error(request, pk)
    if err:
        return err
    try:
        rapport = generate_pdf_for_scan(scan, force_regenerate=True)
    except Exception as exc:
        logger.exception('Régénération explicite échouée pour scan #%s', scan.id)
        return Response(
            {'error': f'Impossible de régénérer le rapport PDF: {exc}', 'scan_id': scan.id},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    return Response({
        'rapport': {
            'id': rapport.id,
            'scan_id': scan.id,
            'date_generation': rapport.date_generation,
            'download_url': f'/api/scans/{scan.id}/rapport/download/',
        }
    }, status=status.HTTP_201_CREATED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_rapport_download(request, pk):
    """
    Télécharger le PDF du rapport.

    GET /api/scans/<pk>/rapport/download/
    """
    scan, err = _get_scan_or_error(request, pk)
    if err:
        return err

    force_regenerate = request.query_params.get('force_regenerate', '').lower() in ('1', 'true', 'yes')
    rapport = None if force_regenerate else _latest_rapport(scan)
    if rapport is None:
        try:
            rapport = generate_pdf_for_scan(scan, force_regenerate=force_regenerate)
        except Exception as exc:
            logger.exception('Génération PDF pour téléchargement échouée scan #%s', scan.id)
            return Response(
                {'error': f'Rapport PDF indisponible: {exc}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    pdf_path = resolve_pdf_absolute_path(rapport)
    if not pdf_path.is_file():
        # Tenter une régénération si le fichier a disparu
        try:
            rapport = generate_pdf_for_scan(scan, force_regenerate=force_regenerate)
            pdf_path = resolve_pdf_absolute_path(rapport)
        except Exception as exc:
            return Response(
                {'error': f'Fichier PDF introuvable: {exc}'},
                status=status.HTTP_404_NOT_FOUND,
            )

    if not pdf_path.is_file():
        raise Http404('Fichier PDF introuvable sur le serveur')

    filename = pdf_path.name
    response = FileResponse(
        open(pdf_path, 'rb'),
        content_type='application/pdf',
        as_attachment=True,
        filename=filename,
    )
    return response


@api_view(['GET'])
@permission_classes([AllowAny])
def scan_report_email_download(request, pk):
    """Telechargement public protege par un jeton signe et temporaire."""
    from .report_email import REPORT_DOWNLOAD_SALT

    token = request.query_params.get('token')
    if not token:
        return Response({'error': 'Jeton manquant'}, status=status.HTTP_403_FORBIDDEN)

    max_age = getattr(settings, 'REPORT_EMAIL_LINK_MAX_AGE', 7 * 24 * 60 * 60)
    try:
        payload = signing.loads(token, salt=REPORT_DOWNLOAD_SALT, max_age=max_age)
    except signing.SignatureExpired:
        return Response({'error': 'Lien expire'}, status=status.HTTP_410_GONE)
    except signing.BadSignature:
        return Response({'error': 'Lien invalide'}, status=status.HTTP_403_FORBIDDEN)

    if int(payload.get('scan_id', -1)) != int(pk):
        return Response({'error': 'Lien invalide'}, status=status.HTTP_403_FORBIDDEN)

    try:
        scan = Scan.objects.get(pk=pk)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan introuvable'}, status=status.HTTP_404_NOT_FOUND)

    rapport = _latest_rapport(scan)
    if rapport is None:
        try:
            rapport = generate_pdf_for_scan(scan)
        except Exception as exc:
            logger.exception('Generation du PDF via lien email echouee scan #%s', scan.id)
            return Response(
                {'error': f'Rapport PDF indisponible: {exc}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    pdf_path = resolve_pdf_absolute_path(rapport)
    if not pdf_path.is_file():
        return Response({'error': 'Fichier PDF introuvable'}, status=status.HTTP_404_NOT_FOUND)

    return FileResponse(
        open(pdf_path, 'rb'),
        content_type='application/pdf',
        as_attachment=True,
        filename=pdf_path.name,
    )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_report_qr(request, pk):
    """Retourne un QR Code SVG pointant vers le rapport du scan."""
    from reportlab.graphics import renderSVG
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing

    from .report_email import build_report_url

    scan, err = _get_scan_or_error(request, pk)
    if err:
        return err

    qr = QrCodeWidget(build_report_url(scan))
    x1, y1, x2, y2 = qr.getBounds()
    width, height = x2 - x1, y2 - y1
    size = 220
    drawing = Drawing(
        size,
        size,
        transform=[size / width, 0, 0, size / height, 0, 0],
    )
    drawing.add(qr)
    svg = renderSVG.drawToString(drawing)
    return HttpResponse(svg, content_type='image/svg+xml')

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_export_json(request, pk):
    """
    Export JSON structuré du rapport.

    GET /api/scans/<pk>/export/json/
    """
    scan, err = _get_scan_or_error(request, pk)
    if err:
        return err

    payload = build_json_export(scan)

    try:
        from .notification_service import notify_report_ready
        notify_report_ready(scan, 'JSON')
    except Exception:
        logger.exception('Notification export JSON échouée scan #%s', scan.id)

    return Response(payload, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_export_excel(request, pk):
    """
    Télécharger le rapport au format Excel (.xlsx).

    GET /api/scans/<pk>/export/excel/
    """
    scan, err = _get_scan_or_error(request, pk)
    if err:
        return err

    try:
        content = generate_excel_bytes(scan)
    except Exception as exc:
        logger.exception('Export Excel échoué scan #%s', scan.id)
        return Response(
            {'error': f'Impossible de générer le rapport Excel: {exc}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    try:
        from .notification_service import notify_report_ready
        notify_report_ready(scan, 'Excel')
    except Exception:
        logger.exception('Notification export Excel échouée scan #%s', scan.id)

    filename = excel_filename_for_scan(scan)
    response = FileResponse(
        io.BytesIO(content),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        filename=filename,
    )
    return response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def scan_rapport_email(request, pk):
    """
    Renvoi manuel du rapport par email (PDF en pièce jointe).

    POST /api/scans/<pk>/rapport/email/
    Body optionnel: { "email": "dest@example.com" } ou { "emails": ["a@x.com", ...] }
    """
    scan, err = _get_scan_or_error(request, pk)
    if err:
        return err

    from .report_email import send_scan_report_email

    force_regenerate = request.query_params.get('force_regenerate', '').lower() in ('1', 'true', 'yes')
    rapport = None if force_regenerate else _latest_rapport(scan)
    if rapport is None:
        try:
            rapport = generate_pdf_for_scan(scan, force_regenerate=force_regenerate)
        except Exception as exc:
            logger.exception('Génération PDF avant email échouée scan #%s', scan.id)
            return Response(
                {
                    'success': False,
                    'error': f'Impossible de générer le rapport PDF: {exc}',
                    'scan_id': scan.id,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    extra_emails = []
    single = request.data.get('email')
    many = request.data.get('emails')
    if single:
        extra_emails.append(str(single).strip())
    if isinstance(many, list):
        extra_emails.extend(str(e).strip() for e in many if e)

    result = send_scan_report_email(
        scan,
        rapport=rapport,
        extra_emails=extra_emails or None,
    )

    if result.get('success'):
        return Response(
            {
                'success': True,
                'message': 'Rapport envoyé par email avec succès.',
                'recipients': result.get('recipients', []),
                'scan_id': scan.id,
            },
            status=status.HTTP_200_OK,
        )

    if result.get('skipped'):
        return Response(
            {
                'success': False,
                'skipped': True,
                'error': result.get('error') or 'Aucun destinataire email disponible',
                'recipients': result.get('recipients', []),
                'scan_id': scan.id,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response(
        {
            'success': False,
            'error': result.get('error') or "Échec de l'envoi email",
            'recipients': result.get('recipients', []),
            'scan_id': scan.id,
        },
        status=status.HTTP_502_BAD_GATEWAY,
    )
