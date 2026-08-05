from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import path
from rest_framework.test import APITestCase

from .models import Scan
from .scan_submission import scans_list
from .tasks import execute_scan


urlpatterns = [path('api/scans/', scans_list)]
User = get_user_model()


@override_settings(ROOT_URLCONF=__name__)
class AsyncScanSubmissionTests(APITestCase):
    @patch('scanner.scan_submission.execute_scan.apply_async')
    def test_submit_returns_tracking_id_without_running_scan(self, apply_async):
        user = User.objects.create_user(
            username='scanadmin', email='scanadmin@example.com',
            password='StrongPass123!', role='admin',
        )
        self.client.force_authenticate(user=user)

        response = self.client.post(
            '/api/scans/',
            {'url': '8.8.8.8', 'options': {'zap': True}, 'email': 'ops@example.com'},
            format='json',
        )

        self.assertEqual(response.status_code, 202)
        scan_id = response.data['tracking_ids'][0]
        self.assertEqual(response.data['scans'][0]['scan_id'], scan_id)
        self.assertEqual(response.data['scans'][0]['status'], Scan.Status.PENDING)
        scan = Scan.objects.get(pk=scan_id)
        self.assertEqual(scan.status, Scan.Status.PENDING)
        self.assertTrue(scan.celery_task_id)
        apply_async.assert_called_once()
        self.assertEqual(apply_async.call_args.kwargs['task_id'], scan.celery_task_id)

    @patch('scanner.scan_submission.execute_scan.apply_async')
    def test_multiple_targets_return_one_tracking_id_each(self, apply_async):
        user = User.objects.create_user(
            username='batchadmin', email='batchadmin@example.com',
            password='StrongPass123!', role='admin',
        )
        self.client.force_authenticate(user=user)

        response = self.client.post(
            '/api/scans/', {'urls': ['8.8.8.8', '1.1.1.1']}, format='json'
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(len(response.data['tracking_ids']), 2)
        self.assertEqual(Scan.objects.filter(status=Scan.Status.PENDING).count(), 2)
        self.assertEqual(apply_async.call_count, 2)

    @patch('scanner.scan_submission.execute_scan.apply_async')
    def test_duplicate_active_target_reuses_existing_scan(self, apply_async):
        user = User.objects.create_user(
            username='duplicate-admin', email='duplicate@example.com',
            password='StrongPass123!', role='admin',
        )
        self.client.force_authenticate(user=user)
        existing = Scan.objects.create(
            domaine='example.com', status=Scan.Status.RUNNING,
            celery_task_id='existing-task', created_by=user,
        )

        response = self.client.post('/api/scans/', {'url': 'example.com'}, format='json')

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data['scans'][0]['scan_id'], existing.id)
        self.assertTrue(response.data['scans'][0]['reused'])
        self.assertEqual(Scan.objects.filter(created_by=user, domaine='example.com').count(), 1)
        apply_async.assert_not_called()
    @patch('scanner.report_pipeline.finalize_scan_report', return_value={'pdf_ok': True, 'errors': []})
    @patch('scanner.tasks._run_pipeline')
    def test_worker_persists_running_then_completed(self, pipeline, _report):
        pipeline.return_value = {
            'success': True, 'sslscan_raw': 'ok', 'nmap_raw': 'ok',
            'openssl_raw': 'ok', 'protocols': [], 'vulnerabilities': [],
            'cves': [], 'score_risque_ia': 1.0,
        }
        scan = Scan.objects.create(domaine='8.8.8.8')

        result = execute_scan.run(scan.id)

        scan.refresh_from_db()
        self.assertEqual(result['status'], Scan.Status.COMPLETED)
        self.assertEqual(scan.status, Scan.Status.COMPLETED)
        self.assertIsNotNone(scan.started_at)
        self.assertIsNotNone(scan.completed_at)

    @patch('scanner.tasks._run_pipeline', side_effect=RuntimeError('scanner unavailable'))
    def test_worker_persists_failed_status(self, _pipeline):
        scan = Scan.objects.create(domaine='8.8.8.8')

        with self.assertRaises(RuntimeError):
            execute_scan.run(scan.id)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.FAILED)
        self.assertIn('scanner unavailable', scan.error_message)
