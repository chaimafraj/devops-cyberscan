import logging

from django.db import transaction

from .models import RealtimeEvent

logger = logging.getLogger(__name__)

RESOURCE_MAP = {
    'scan.queued': ['scans', 'dashboard'],
    'scan.running': ['scans', 'dashboard'],
    'scan.completed': ['scans', 'dashboard', 'alerts', 'chatbot', 'reports', 'notifications'],
    'scan.failed': ['scans', 'dashboard', 'notifications'],
    'scan.cancelled': ['scans', 'dashboard', 'notifications'],
    'notification.created': ['notifications'],
    'notification.updated': ['notifications'],
    'notification.deleted': ['notifications'],
    'vulnerability.created': ['dashboard', 'alerts', 'chatbot', 'reports'],
    'vulnerability.deleted': ['dashboard', 'alerts', 'chatbot', 'reports'],
    'report.created': ['reports', 'scans', 'notifications'],
}


def publish_event(event_type, scan=None, payload=None):
    event = RealtimeEvent.objects.create(
        event_type=event_type,
        scan=scan,
        payload={**(payload or {}), 'resources': RESOURCE_MAP.get(event_type, [])},
    )
    logger.info('realtime_event_created event_id=%s type=%s scan_id=%s',
                event.id, event_type, getattr(scan, 'id', None))
    return event


def publish_on_commit(event_type, scan=None, payload=None):
    scan_id = getattr(scan, 'id', scan)

    def _publish():
        from .models import Scan
        resolved_scan = Scan.objects.filter(pk=scan_id).first() if scan_id else None
        publish_event(event_type, resolved_scan, payload)

    transaction.on_commit(_publish)
