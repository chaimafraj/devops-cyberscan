from django.db.models import Avg, Count, Q

from .access import visible_scans
from .alert_service import alert_stats, build_alerts
from .cve_data import collect_scan_cves
from .models import Scan
from .scan_queries import scan_alert_queryset, scan_summary_queryset
from .serializers import ScanSummarySerializer


def build_dashboard_payload(user):
    scans = visible_scans(user)
    aggregate = scans.aggregate(total=Count('id'), average=Avg('score_risque_ia'))
    status_counts = {item['status']: item['count'] for item in scans.values('status').annotate(count=Count('id'))}
    scan_risk_counts = scans.aggregate(
        critical=Count('id', filter=Q(score_risque_ia__gte=9)),
        high=Count('id', filter=Q(score_risque_ia__gte=7, score_risque_ia__lt=9)),
        medium=Count('id', filter=Q(score_risque_ia__gte=4, score_risque_ia__lt=7)),
        low=Count('id', filter=Q(score_risque_ia__lt=4)),
    )
    completed = scan_alert_queryset(scans.filter(status=Scan.Status.COMPLETED)).order_by('-date_scan')
    vulnerabilities = alert_stats(build_alerts(list(completed)))
    recent = scan_summary_queryset(scans).order_by('-date_scan')[:5]
    total_recommendations = sum(
        len(collect_scan_cves(scan, scan.resultats_ssl if isinstance(scan.resultats_ssl, dict) else {}))
        for scan in scans.prefetch_related('cves')
    )
    return {
        'total_scans': aggregate['total'] or 0,
        'avg_risk_score': round(float(aggregate['average'] or 0), 1),
        # Backward-compatible keys now reflect the vulnerability cards shown by the UI.
        'critical_count': vulnerabilities['critiques'],
        'medium_count': vulnerabilities['moyennes'],
        'low_count': vulnerabilities['faibles'],
        'vulnerability_stats': vulnerabilities,
        'scan_risk_counts': scan_risk_counts,
        'scan_status_counts': {
            'pending': status_counts.get(Scan.Status.PENDING, 0),
            'running': status_counts.get(Scan.Status.RUNNING, 0),
            'completed': status_counts.get(Scan.Status.COMPLETED, 0),
            'failed': status_counts.get(Scan.Status.FAILED, 0),
        },
        'total_recommandations': total_recommendations,
        'recent_scans': ScanSummarySerializer(recent, many=True).data,
    }
