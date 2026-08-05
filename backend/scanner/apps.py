from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'

    def ready(self):
        # Charge le module signals (documentation / extensions futures).
        # La finalisation PDF+email est déclenchée via report_pipeline
        # après la création des CVE (voir views.scans_list).
        try:
            from . import signals  # noqa: F401
        except Exception:
            pass
