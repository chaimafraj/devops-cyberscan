import ipaddress
import logging
import re
from urllib.parse import urlsplit
from uuid import uuid4

from celery import current_app
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .access import visible_scans
from .models import Client, Scan
from .realtime_service import publish_event, publish_on_commit
from .scan_queries import scan_summary_queryset
from .serializers import ScanSummarySerializer
from .tasks import execute_scan

logger = logging.getLogger(__name__)
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,63}$'
)


class InvalidScanTarget(ValueError):
    pass


def validate_scan_target(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidScanTarget('la cible doit être un domaine ou une adresse IP')

    value = raw.strip()
    if '://' in value:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise InvalidScanTarget('URL HTTP(S) invalide')
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise InvalidScanTarget('identifiants, requête et fragment non autorisés')
        if parsed.path not in ('', '/'):
            raise InvalidScanTarget('seul le domaine cible est autorisé')
        try:
            port = parsed.port
        except ValueError as exc:
            raise InvalidScanTarget('port invalide') from exc
        host = parsed.hostname
    else:
        if any(character in value for character in '/?#@'):
            raise InvalidScanTarget('format de cible invalide')
        host = value
        port = None
        if value.count(':') == 1:
            candidate_host, candidate_port = value.rsplit(':', 1)
            if not candidate_port.isdigit():
                raise InvalidScanTarget('port invalide')
            host = candidate_host
            port = int(candidate_port)
        elif ':' in value:
            raise InvalidScanTarget('IPv6 non pris en charge')

    host = host.strip().rstrip('.').lower()
    if not host:
        raise InvalidScanTarget('hôte manquant')
    if port is not None and not 1 <= port <= 65535:
        raise InvalidScanTarget('le port doit être compris entre 1 et 65535')

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not DOMAIN_RE.fullmatch(host):
            raise InvalidScanTarget('nom de domaine ou adresse IP invalide')

    return f'{host}:{port}' if port is not None else host


def list_scans(request):
    scans = scan_summary_queryset(visible_scans(request.user)).order_by('-date_scan')
    search = request.query_params.get('search', '').strip()
    risk = request.query_params.get('risk', '').upper()
    status_filter = request.query_params.get('status', '').upper()
    if search:
        scans = scans.filter(domaine__icontains=search)
    if risk == 'HIGH':
        scans = scans.filter(score_risque_ia__gte=7)
    elif risk == 'MEDIUM':
        scans = scans.filter(score_risque_ia__gte=4, score_risque_ia__lt=7)
    elif risk == 'LOW':
        scans = scans.filter(score_risque_ia__lt=4)
    if status_filter in Scan.Status.values:
        scans = scans.filter(status=status_filter)
    try:
        page = max(int(request.query_params.get('page', 1)), 1)
        page_size = min(max(int(request.query_params.get('page_size', 10)), 1), 100)
    except (TypeError, ValueError):
        return Response({'error': 'Pagination invalide'}, status=status.HTTP_400_BAD_REQUEST)
    total = scans.count()
    start = (page - 1) * page_size
    return Response({
        'results': ScanSummarySerializer(scans[start:start + page_size], many=True).data,
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': max(1, (total + page_size - 1) // page_size),
    })


def submit_scans(request):
    raw_targets = request.data.get('urls')
    if raw_targets is None:
        raw_targets = [request.data.get('url')] if request.data.get('url') else []
    if not isinstance(raw_targets, list) or not raw_targets:
        return Response({'error': 'Aucune URL fournie'}, status=status.HTTP_400_BAD_REQUEST)
    if len(raw_targets) > 20:
        return Response({'error': 'Maximum 20 cibles par requête'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        targets = [validate_scan_target(raw) for raw in raw_targets]
    except InvalidScanTarget as exc:
        return Response({'error': f'Cible invalide: {exc}'}, status=status.HTTP_400_BAD_REQUEST)

    client = None
    if request.user.role != 'admin':
        try:
            client = request.user.client_profile
        except Client.DoesNotExist:
            client = None

    queued = []
    for target in targets:
        existing_scan = Scan.objects.filter(
            created_by=request.user,
            domaine=target,
            status__in=[Scan.Status.PENDING, Scan.Status.RUNNING],
        ).order_by('-date_scan').first()
        if existing_scan is not None:
            queued.append({
                'scan_id': existing_scan.id,
                'task_id': existing_scan.celery_task_id,
                'domaine': target,
                'status': existing_scan.status,
                'status_url': f'/api/scans/{existing_scan.id}/',
                'reused': True,
            })
            continue

        task_id = str(uuid4())
        with transaction.atomic():
            scan = Scan.objects.create(
                domaine=target,
                status=Scan.Status.PENDING,
                celery_task_id=task_id,
                created_by=request.user,
                client=client,
            )
            publish_on_commit('scan.queued', scan, {'status': Scan.Status.PENDING})
        try:
            execute_scan.apply_async(
                args=[
                    scan.id,
                    request.data.get('is_production', True),
                    request.data.get('has_financial_data', False),
                    request.data.get('options', {}),
                    request.data.get('email'),
                ],
                task_id=task_id,
            )
        except Exception as exc:
            logger.exception('scan_queue_failed scan_id=%s error_type=%s', scan.id, exc.__class__.__name__)
            scan.status = Scan.Status.FAILED
            scan.error_message = 'Mise en file Celery impossible. Vérifiez Redis et le worker Celery.'
            scan.save(update_fields=['status', 'error_message'])
            publish_event('scan.failed', scan, {'status': Scan.Status.FAILED})
            try:
                from .notification_service import notify_scan_failed
                notify_scan_failed(scan, scan.error_message)
            except Exception:
                logger.warning('scan_queue_notification_failed scan_id=%s', scan.id, exc_info=True)
            return Response(
                {'error': scan.error_message, 'scan_id': scan.id},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        queued.append({
            'scan_id': scan.id,
            'task_id': task_id,
            'domaine': target,
            'status': Scan.Status.PENDING,
            'status_url': f'/api/scans/{scan.id}/',
        })

    return Response(
        {'scans': queued, 'tracking_ids': [item['scan_id'] for item in queued]},
        status=status.HTTP_202_ACCEPTED,
    )


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def scans_list(request):
    if request.method == 'GET':
        return list_scans(request)
    return submit_scans(request)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_scan(request, pk):
    """Interrompt un scan en attente ou en cours appartenant à l'utilisateur."""
    with transaction.atomic():
        scan = visible_scans(request.user).select_for_update().filter(pk=pk).first()
        if scan is None:
            return Response({'error': 'Scan introuvable'}, status=status.HTTP_404_NOT_FOUND)

        if scan.status == Scan.Status.CANCELLED:
            return Response({
                'scan_id': scan.id,
                'status': scan.status,
                'message': 'Le scan est déjà annulé.',
            }, status=status.HTTP_200_OK)

        if scan.status not in (Scan.Status.PENDING, Scan.Status.RUNNING):
            return Response(
                {'error': 'Seul un scan en attente ou en cours peut être annulé.'},
                status=status.HTTP_409_CONFLICT,
            )

        task_id = scan.celery_task_id
        scan.status = Scan.Status.CANCELLED
        scan.completed_at = timezone.now()
        scan.error_message = "Scan annulé par l'utilisateur."
        scan.save(update_fields=['status', 'completed_at', 'error_message'])
        publish_on_commit('scan.cancelled', scan, {'status': Scan.Status.CANCELLED})

    if task_id:
        try:
            current_app.control.revoke(task_id, terminate=False)
        except Exception:
            logger.warning('scan_revoke_failed scan_id=%s task_id=%s', scan.id, task_id, exc_info=True)

    try:
        from .notification_service import notify_scan_cancelled
        notify_scan_cancelled(scan)
    except Exception:
        logger.warning('scan_cancel_notification_failed scan_id=%s', scan.id, exc_info=True)

    return Response({
        'scan_id': scan.id,
        'status': Scan.Status.CANCELLED,
        'message': 'Scan annulé avec succès.',
    }, status=status.HTTP_200_OK)
