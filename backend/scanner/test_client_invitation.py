from smtplib import SMTPException
from unittest.mock import patch

from rest_framework.test import APITestCase

from .models import Client, User


class ClientInvitationTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin-invitations',
            email='admin@example.com',
            password='StrongPass123!',
            role='admin',
        )
        self.client.force_authenticate(self.admin)
        self.payload = {
            'nom': 'Client Invitation',
            'username': 'client-invitation',
            'email': 'client-invitation@example.com',
        }

    @patch('scanner.client_views.send_mail', return_value=1)
    def test_client_is_created_only_after_email_delivery(self, send_mail):
        response = self.client.post('/api/clients/', self.payload, format='json')

        self.assertEqual(response.status_code, 201)
        self.assertTrue(Client.objects.filter(email=self.payload['email']).exists())
        self.assertTrue(User.objects.filter(username=self.payload['username']).exists())
        self.assertEqual(send_mail.call_args.kwargs['recipient_list'], [self.payload['email']])
        self.assertIn('email_status', response.data)

    @patch(
        'scanner.client_views.send_mail',
        side_effect=SMTPException('SMTP unavailable'),
    )
    def test_smtp_exception_rolls_back_client_and_user(self, _send_mail):
        response = self.client.post('/api/clients/', self.payload, format='json')

        self.assertEqual(response.status_code, 502)
        self.assertFalse(Client.objects.filter(email=self.payload['email']).exists())
        self.assertFalse(User.objects.filter(username=self.payload['username']).exists())
        self.assertIn('error', response.data)

    @patch('scanner.client_views.send_mail', return_value=0)
    def test_zero_delivered_messages_rolls_back_client_and_user(self, _send_mail):
        response = self.client.post('/api/clients/', self.payload, format='json')

        self.assertEqual(response.status_code, 502)
        self.assertFalse(Client.objects.filter(email=self.payload['email']).exists())
        self.assertFalse(User.objects.filter(username=self.payload['username']).exists())

