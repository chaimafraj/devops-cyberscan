from __future__ import annotations

import json
import logging
import time

from django.db import close_old_connections
from django.db.models import Q
from django.http import StreamingHttpResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

from .models import Client, RealtimeEvent
from .notification_views import _notifications_for_user

logger = logging.getLogger(__name__)


def _visible_events(user, after_id=0):
    queryset = RealtimeEvent.objects.select_related('scan').filter(id__gt=after_id)
    if getattr(user, 'role', None) == 'admin':
        return queryset
    try:
        client_id = user.client_profile.id
    except (Client.DoesNotExist, AttributeError):
        client_id = None
    ownership = Q(scan__created_by=user)
    if client_id is not None:
        ownership |= Q(scan__client_id=client_id)
    return queryset.filter(ownership)


def _event_payload(event, user):
    return {
        'id': event.id,
        'type': event.event_type,
        'scan_id': event.scan_id,
        'payload': event.payload,
        'unread_count': _notifications_for_user(user).filter(lu=False).count(),
        'timestamp': event.created_at.isoformat(),
    }


def _sse(event_name, data, event_id=None):
    lines = []
    if event_id is not None:
        lines.append(f'id: {event_id}')
    lines.append(f'event: {event_name}')
    lines.append('data: ' + json.dumps(data, ensure_ascii=False, separators=(',', ':')))
    return '\n'.join(lines) + '\n\n'


def event_stream(user, last_event_id=0, once=False, poll_seconds=1.0, max_seconds=300):
    started = time.monotonic()
    cursor = max(int(last_event_id or 0), 0)
    if cursor == 0:
        latest = _visible_events(user, 0).order_by('-id').values_list('id', flat=True).first()
        cursor = latest or 0
    initial_count = _notifications_for_user(user).filter(lu=False).count()
    yield _sse('snapshot', {
        'unread_count': initial_count,
        'resources': ['dashboard', 'scans', 'alerts', 'notifications'],
    }, cursor)
    if once:
        return
    while time.monotonic() - started < max_seconds:
        close_old_connections()
        events = list(_visible_events(user, cursor).order_by('id')[:100])
        if events:
            for event in events:
                cursor = event.id
                yield _sse(event.event_type, _event_payload(event, user), event.id)
        else:
            yield ': heartbeat\n\n'
        time.sleep(poll_seconds)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def realtime_events(request):
    try:
        last_event_id = int(request.headers.get('Last-Event-ID') or request.query_params.get('last_event_id') or 0)
    except (TypeError, ValueError):
        last_event_id = 0
    once = request.query_params.get('once', '').lower() in {'1', 'true', 'yes'}
    response = StreamingHttpResponse(
        event_stream(request.user, last_event_id=last_event_id, once=once),
        content_type='text/event-stream; charset=utf-8',
    )
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['X-Accel-Buffering'] = 'no'
    response['Connection'] = 'keep-alive'
    logger.info('realtime_stream_opened user_id=%s last_event_id=%s once=%s',
                request.user.id, last_event_id, once)
    return response