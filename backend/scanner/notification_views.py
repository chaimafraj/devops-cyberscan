"""
API REST des notifications CyberScan.
"""
from __future__ import annotations

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import Client, Notification, Scan
from .serializers import NotificationSerializer
from .realtime_service import publish_event


def _user_can_access_scan(user, scan: Scan) -> bool:
    if getattr(user, 'role', None) == 'admin':
        return True
    if scan.created_by_id == user.id:
        return True
    try:
        return scan.client_id == user.client_profile.id
    except (Client.DoesNotExist, AttributeError):
        return False


def _notifications_for_user(user):
    qs = Notification.objects.select_related('scan')
    if getattr(user, 'role', None) == 'admin':
        return qs.all()
    try:
        client_id = user.client_profile.id
    except (Client.DoesNotExist, AttributeError):
        client_id = None
    if client_id is not None:
        return qs.filter(scan__client_id=client_id)
    return qs.filter(scan__created_by=user)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def notifications_list(request):
    """
    GET /api/notifications/
    """
    qs = _notifications_for_user(request.user)
    if request.GET.get('unread') == 'true':
        qs = qs.filter(lu=False)
    unread_count = _notifications_for_user(request.user).filter(lu=False).count()
    serializer = NotificationSerializer(qs[:100], many=True)
    return Response(
        {'notifications': serializer.data, 'unread_count': unread_count},
        status=status.HTTP_200_OK,
    )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def notifications_unread_count(request):
    """
    GET /api/notifications/unread-count/
    """
    count = _notifications_for_user(request.user).filter(lu=False).count()
    return Response({'unread_count': count}, status=status.HTTP_200_OK)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def notifications_mark_all_read(request):
    """PATCH /api/notifications/read-all/"""
    unread = _notifications_for_user(request.user).filter(lu=False)
    scan_ids = list(unread.values_list('scan_id', flat=True).distinct())
    updated_count = unread.update(lu=True)
    for scan in Scan.objects.filter(id__in=scan_ids):
        publish_event('notification.updated', scan, {'all_read': True})
    return Response(
        {'success': True, 'updated_count': updated_count},
        status=status.HTTP_200_OK,
    )


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def notification_mark_read(request, pk):
    """
    PATCH /api/notifications/<id>/read/
    """
    try:
        notification = Notification.objects.select_related('scan').get(pk=pk)
    except Notification.DoesNotExist:
        return Response({'error': 'Notification introuvable'}, status=status.HTTP_404_NOT_FOUND)

    if not _user_can_access_scan(request.user, notification.scan):
        return Response({'error': {'code': 'FORBIDDEN', 'message': 'Accès refusé'}}, status=status.HTTP_403_FORBIDDEN)

    if not notification.lu:
        notification.lu = True
        notification.save(update_fields=['lu'])
        publish_event('notification.updated', notification.scan, {'notification_id': notification.id, 'read': True})

    return Response(
        {'success': True, 'notification': NotificationSerializer(notification).data},
        status=status.HTTP_200_OK,
    )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def notification_delete(request, pk):
    """
    DELETE /api/notifications/<id>/
    """
    try:
        notification = Notification.objects.select_related('scan').get(pk=pk)
    except Notification.DoesNotExist:
        return Response({'error': 'Notification introuvable'}, status=status.HTTP_404_NOT_FOUND)

    if not _user_can_access_scan(request.user, notification.scan):
        return Response({'error': {'code': 'FORBIDDEN', 'message': 'Accès refusé'}}, status=status.HTTP_403_FORBIDDEN)

    scan = notification.scan
    notification_id = notification.id
    notification.delete()
    publish_event('notification.deleted', scan, {'notification_id': notification_id})
    return Response(status=status.HTTP_204_NO_CONTENT)

