from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .access import visible_scans
from .alert_service import alert_stats, build_alerts
from .models import Scan
from .scan_queries import scan_alert_queryset


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def alertes_list(request):
    scans = scan_alert_queryset(
        visible_scans(request.user).filter(status=Scan.Status.COMPLETED)
    ).order_by('-date_scan')[:50]
    alerts = build_alerts(list(scans))
    return Response({'alertes': alerts, 'stats': alert_stats(alerts)})