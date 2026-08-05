from django.db.models import Count, Exists, OuterRef

from .models import Rapport


def scan_summary_queryset(queryset):
    return queryset.select_related('client', 'created_by').prefetch_related('cves').annotate(
        manual_vulnerabilities_count=Count('vulnerabilites_manuelles', distinct=True),
        has_rapport_value=Exists(Rapport.objects.filter(scan_id=OuterRef('pk'))),
    )


def scan_alert_queryset(queryset):
    return queryset.prefetch_related('cves', 'vulnerabilites_manuelles')