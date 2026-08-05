from django.contrib import admin
from .models import Notification, Scan, CVE, Client, Rapport


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('titre', 'type', 'niveau', 'lu', 'scan', 'date_creation')
    list_filter = ('type', 'niveau', 'lu')
    search_fields = ('titre', 'message', 'scan__domaine')


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('domaine', 'date_scan', 'score_risque_ia', 'client')
    search_fields = ('domaine',)


@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'scan', 'cvss_score')
    search_fields = ('cve_id',)


@admin.register(Rapport)
class RapportAdmin(admin.ModelAdmin):
    list_display = ('scan', 'date_generation', 'chemin_pdf')


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ('nom', 'email', 'is_active')
