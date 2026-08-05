from itertools import islice
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import path
from rest_framework.test import APITestCase, APIRequestFactory, force_authenticate

from .dashboard_service import build_dashboard_payload
from .models import Client, Notification, RealtimeEvent, Scan
from .notification_service import create_notification
from .realtime_views import event_stream, realtime_events
from .scan_submission import scans_list
from .tasks import execute_scan
from .views import dashboard_stats

User = get_user_model()
urlpatterns = [
    path('api/dashboard-stats/', dashboard_stats),
    path('api/scans/', scans_list),
    path('api/realtime/events/', realtime_events),
]


@override_settings(ROOT_URLCONF=__name__)
class RealtimeSynchronizationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='sync-admin', email='sync@example.com', password='StrongPass123!', role='admin'
        )
        self.client.force_authenticate(self.user)

    def test_dashboard_counts_medium_vulnerabilities_not_medium_scans(self):
        Scan.objects.create(
            domaine='medium.example.com', status=Scan.Status.COMPLETED,
            score_risque_ia=8.0, created_by=self.user,
            resultats_ssl={'zap_findings': [{'risk': 'Medium', 'name': 'CSP absente'}]},
        )
        payload = build_dashboard_payload(self.user)
        self.assertEqual(payload['medium_count'], 1)
        self.assertEqual(payload['vulnerability_stats']['moyennes'], 1)
        self.assertEqual(payload['scan_risk_counts']['medium'], 0)

    def test_dashboard_is_fresh_lightweight_and_no_store(self):
        Scan.objects.create(
            domaine='fresh.example.com', status=Scan.Status.COMPLETED,
            score_risque_ia=5.25, created_by=self.user,
        )
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get('/api/dashboard-stats/')
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(queries), 12)
        self.assertIn('no-store', response['Cache-Control'])
        recent = response.data['recent_scans'][0]
        self.assertEqual(recent['status'], Scan.Status.COMPLETED)
        self.assertNotIn('resultats_ssl', recent)

    @patch('scanner.scan_submission.execute_scan.apply_async')
    def test_scan_is_immediately_visible_as_pending(self, apply_async):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post('/api/scans/', {'url': 'https://example.com'}, format='json')
        self.assertEqual(response.status_code, 202)
        scan_id = response.data['scans'][0]['scan_id']
        history = self.client.get('/api/scans/')
        self.assertEqual(history.data['results'][0]['id'], scan_id)
        self.assertEqual(history.data['results'][0]['status'], Scan.Status.PENDING)
        self.assertTrue(RealtimeEvent.objects.filter(scan_id=scan_id, event_type='scan.queued').exists())

    def test_sse_snapshot_contains_real_unread_count(self):
        scan = Scan.objects.create(domaine='events.example.com', created_by=self.user)
        create_notification(scan, 'Nouvelle', 'Description', 'scan_finished')
        request = APIRequestFactory().get('/api/realtime/events/?once=true')
        force_authenticate(request, self.user)
        response = realtime_events(request)
        chunk = b''.join(response.streaming_content).decode('utf-8')
        self.assertIn('event: snapshot', chunk)
        self.assertIn('"unread_count":1', chunk)
        self.assertIn('text/event-stream', response['Content-Type'])

    def test_event_stream_delivers_persisted_event(self):
        scan = Scan.objects.create(domaine='event.example.com', created_by=self.user)
        previous = RealtimeEvent.objects.create(event_type='scan.running', scan=scan, payload={})
        event = RealtimeEvent.objects.create(event_type='scan.completed', scan=scan, payload={})
        chunks = list(islice(event_stream(self.user, last_event_id=previous.id, max_seconds=0.01, poll_seconds=0), 2))
        self.assertIn('event: snapshot', chunks[0])
        self.assertIn('event: scan.completed', chunks[1])
        self.assertIn(f'id: {event.id}', chunks[1])

    @patch('scanner.report_pipeline.finalize_scan_report')
    @patch('scanner.tasks._run_pipeline')
    def test_worker_marks_completed_before_report_generation(self, pipeline, report):
        pipeline.return_value = {
            'success': True, 'sslscan_raw': 'ok', 'nmap_raw': 'ok', 'openssl_raw': 'ok',
            'protocols': [], 'vulnerabilities': [], 'cves': [], 'score_risque_ia': 5.26,
        }
        scan = Scan.objects.create(domaine='worker.example.com', created_by=self.user)

        def assert_completed(current_scan, **kwargs):
            current_scan.refresh_from_db()
            self.assertEqual(current_scan.status, Scan.Status.COMPLETED)
            return {'pdf_ok': True, 'errors': []}

        report.side_effect = assert_completed
        with self.captureOnCommitCallbacks(execute=True):
            execute_scan.run(scan.id)
        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.COMPLETED)
        self.assertEqual(scan.score_risque_ia, 5.3)
        self.assertTrue(RealtimeEvent.objects.filter(scan=scan, event_type='scan.completed').exists())