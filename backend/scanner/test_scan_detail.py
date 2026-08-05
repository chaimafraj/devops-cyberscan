from django.contrib.auth.models import User
from rest_framework.test import APITestCase

from .models import Notification, Rapport, RealtimeEvent, Scan, User


class ScanDetailApiTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="auditor", password="secret")
        self.client.force_authenticate(self.user)
        self.scan = Scan.objects.create(
            domaine="audit.example",
            created_by=self.user,
            status=Scan.Status.COMPLETED,
            score_risque_ia=8.2,
            resultats_ssl={
                "scan_duration_seconds": 12.5,
                "tool_executions": {
                    "sslscan": {
                        "success": True,
                        "duration_seconds": 1.2,
                        "completed_at": "2026-08-03T10:00:01Z",
                    }
                },
            },
        )
        Rapport.objects.create(scan=self.scan, chemin_pdf="rapport.pdf")
        Notification.objects.create(
            scan=self.scan,
            type="report_emailed",
            niveau="success",
            titre="Rapport envoye",
            message="Rapport envoye.",
        )
        RealtimeEvent.objects.create(
            scan=self.scan,
            event_type="scan.completed",
            payload={"status": "COMPLETED"},
        )

    def test_detail_exposes_dynamic_status_duration_and_timeline(self):
        response = self.client.get(f"/api/scans/{self.scan.pk}/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["duration_seconds"], 12.5)
        self.assertEqual(response.data["email_status"], "envoye")
        self.assertEqual(response.data["report_status"], "pret")
        self.assertEqual(response.data["timeline"][0]["type"], "scan.completed")

    def test_qr_endpoint_returns_svg_for_the_authenticated_scan(self):
        response = self.client.get(f"/api/scans/{self.scan.pk}/rapport/qr/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/svg+xml")
        self.assertIn(b"<svg", response.content)