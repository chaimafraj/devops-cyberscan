from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase

from .models import Notification, Scan
from .scan_cancellation import ScanCancelled
from .tasks import execute_scan

User = get_user_model()


class ScanCancellationApiTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='cancel-owner',
            email='cancel-owner@example.com',
            password='StrongPass123!',
            role='admin',
        )
        self.client.force_authenticate(user=self.user)

    @patch('scanner.scan_submission.current_app.control.revoke')
    def test_running_scan_can_be_cancelled(self, revoke):
        scan = Scan.objects.create(
            domaine='example.com',
            status=Scan.Status.RUNNING,
            celery_task_id='task-123',
            created_by=self.user,
        )

        response = self.client.post(reverse('scan_cancel', args=[scan.id]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], Scan.Status.CANCELLED)
        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.CANCELLED)
        self.assertIsNotNone(scan.completed_at)
        revoke.assert_called_once_with('task-123', terminate=False)
        self.assertTrue(
            Notification.objects.filter(scan=scan, type='scan_cancelled').exists()
        )

    @patch('scanner.scan_submission.current_app.control.revoke')
    def test_cancel_is_idempotent(self, revoke):
        scan = Scan.objects.create(
            domaine='example.com',
            status=Scan.Status.PENDING,
            celery_task_id='task-456',
            created_by=self.user,
        )

        first = self.client.post(reverse('scan_cancel', args=[scan.id]))
        second = self.client.post(reverse('scan_cancel', args=[scan.id]))

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            Notification.objects.filter(scan=scan, type='scan_cancelled').count(),
            1,
        )
        revoke.assert_called_once_with('task-456', terminate=False)

    def test_completed_scan_cannot_be_cancelled(self):
        scan = Scan.objects.create(
            domaine='example.com',
            status=Scan.Status.COMPLETED,
            created_by=self.user,
        )

        response = self.client.post(reverse('scan_cancel', args=[scan.id]))

        self.assertEqual(response.status_code, 409)
        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.Status.COMPLETED)


class ScanCancellationWorkerTests(APITestCase):
    @patch('scanner.tasks._run_pipeline')
    def test_worker_does_not_start_a_cancelled_scan(self, pipeline):
        scan = Scan.objects.create(
            domaine='example.com',
            status=Scan.Status.CANCELLED,
        )

        result = execute_scan.run(scan.id)

        self.assertEqual(result['status'], Scan.Status.CANCELLED)
        pipeline.assert_not_called()

    @patch('scanner.tasks._run_pipeline', side_effect=ScanCancelled('arrêt demandé'))
    def test_worker_keeps_cancelled_status(self, _pipeline):
        scan = Scan.objects.create(
            domaine='example.com',
            status=Scan.Status.PENDING,
        )

        result = execute_scan.run(scan.id)

        scan.refresh_from_db()
        self.assertEqual(result['status'], Scan.Status.CANCELLED)
        self.assertEqual(scan.status, Scan.Status.CANCELLED)
        self.assertTrue(
            Notification.objects.filter(scan=scan, type='scan_cancelled').exists()
        )
