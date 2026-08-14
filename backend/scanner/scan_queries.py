from django.db.models import Count, Exists, OuterRef

from .models import Notification, Rapport


def scan_summary_queryset(queryset):
    return queryset.select_related('client', 'created_by').prefetch_related('cves').annotate(
        manual_vulnerabilities_count=Count('vulnerabilites_manuelles', distinct=True),
        has_rapport_value=Exists(Rapport.objects.filter(scan_id=OuterRef('pk'))),
        email_sent_value=Exists(
            Notification.objects.filter(scan_id=OuterRef('pk'), type='report_emailed')
        ),
        email_failed_value=Exists(
            Notification.objects.filter(scan_id=OuterRef('pk'), type='email_failed')
        ),
    )


def scan_alert_queryset(queryset):
    return queryset.prefetch_related('cves', 'vulnerabilites_manuelles')
