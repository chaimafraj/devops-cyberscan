from django.urls import path, reverse
from django.test import override_settings
from rest_framework.test import APITestCase

from . import notification_views
from .models import Client, Notification, Scan, User


urlpatterns = [
    path('api/notifications', notification_views.notifications_list, name='notifications_list'),
    path('api/notifications/read-all', notification_views.notifications_mark_all_read, name='notifications_mark_all_read'),
    path('api/notifications/unread-count', notification_views.notifications_unread_count, name='notifications_unread_count'),
    path('api/notifications/<int:pk>/read', notification_views.notification_mark_read, name='notification_mark_read'),
    path('api/notifications/<int:pk>/', notification_views.notification_delete, name='notification_delete'),
]


@override_settings(ROOT_URLCONF=__name__)
class NotificationApiTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='client-notifications',
            email='client-notifications@example.com',
            password='test-password',
            role='client',
        )
        self.client_profile = Client.objects.create(
            nom='Client notifications',
            email='notifications@example.com',
            user=self.user,
        )
        self.scan = Scan.objects.create(
            domaine='example.com', client=self.client_profile, created_by=self.user
        )
        self.notification = Notification.objects.create(
            titre='Scan terminé',
            message='Le scan est terminé.',
            type='scan_finished',
            niveau='info',
            scan=self.scan,
        )
        self.client.force_authenticate(self.user)

    def test_list_contract_scope_and_unread_count(self):
        other_user = User.objects.create_user(
            username='other-client', email='other-client@example.com',
            password='test-password', role='client',
        )
        other_client = Client.objects.create(
            nom='Autre client', email='other-notifications@example.com', user=other_user,
        )
        other_scan = Scan.objects.create(domaine='other.example.com', client=other_client)
        Notification.objects.create(
            titre='Notification privée', message='Notification d’un autre client.',
            type='scan_finished', niveau='info', scan=other_scan,
        )

        response = self.client.get(reverse('notifications_list'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['unread_count'], 1)
        self.assertEqual(len(response.data['notifications']), 1)
        item = response.data['notifications'][0]
        self.assertEqual(set(item), {'id', 'type', 'title', 'description', 'timestamp', 'read'})
        self.assertEqual(item['id'], self.notification.id)
        self.assertEqual(item['type'], 'success')
        self.assertFalse(item['read'])

    def test_list_is_sorted_newest_first(self):
        newer = Notification.objects.create(
            titre='CVE détectée', message='Une vulnérabilité a été détectée.',
            type='new_cve', niveau='critical', scan=self.scan,
        )

        response = self.client.get(reverse('notifications_list'))

        self.assertEqual(
            [item['id'] for item in response.data['notifications']],
            [newer.id, self.notification.id],
        )
        self.assertEqual(response.data['notifications'][0]['type'], 'alert')

    def test_unread_filter_and_count_are_consistent(self):
        Notification.objects.create(
            titre='Rapport prêt', message='Le rapport est disponible.',
            type='report_ready', niveau='info', lu=True, scan=self.scan,
        )

        list_response = self.client.get(reverse('notifications_list'), {'unread': 'true'})
        count_response = self.client.get(reverse('notifications_unread_count'))

        self.assertEqual(len(list_response.data['notifications']), 1)
        self.assertEqual(list_response.data['unread_count'], 1)
        self.assertEqual(count_response.data, {'unread_count': 1})

    def test_owner_can_mark_notification_as_read(self):
        response = self.client.patch(reverse('notification_mark_read', args=[self.notification.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['success'])
        self.notification.refresh_from_db()
        self.assertTrue(self.notification.lu)

    def test_owner_can_mark_all_notifications_as_read(self):
        Notification.objects.create(
            titre='Rapport prêt', message='Le rapport est disponible.',
            type='report_ready', niveau='info', scan=self.scan,
        )

        response = self.client.patch(reverse('notifications_mark_all_read'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'success': True, 'updated_count': 2})
        self.assertFalse(Notification.objects.filter(scan=self.scan, lu=False).exists())

    def test_other_client_cannot_modify_notification(self):
        other_user = User.objects.create_user(
            username='blocked-client', email='blocked-client@example.com',
            password='test-password', role='client',
        )
        Client.objects.create(
            nom='Client sans accès', email='blocked-notifications@example.com', user=other_user,
        )
        self.client.force_authenticate(other_user)

        response = self.client.patch(reverse('notification_mark_read', args=[self.notification.id]))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error']['code'], 'FORBIDDEN')
        self.assertEqual(response.data['error']['message'], 'Accès refusé')
        self.notification.refresh_from_db()
        self.assertFalse(self.notification.lu)

    def test_authentication_is_required(self):
        self.client.force_authenticate(user=None)
        response = self.client.get(reverse('notifications_list'))
        self.assertEqual(response.status_code, 401)