from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Client, User


class ChangePasswordFlowTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='client-temp',
            email='client-temp@example.com',
            password='TempPass123!',
            role='client',
        )
        self.client_profile = Client.objects.create(
            nom='Client Temp',
            email='client-temp@example.com',
            user=self.user,
            must_change_password=True,
        )
        refresh = RefreshToken.for_user(self.user)
        self.access = str(refresh.access_token)
        self.refresh = str(refresh)

    def test_change_password_clears_flag_and_keeps_token_valid(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access}')

        response = self.client.post(
            '/api/auth/change-password/',
            {
                'old_password': 'TempPass123!',
                'new_password': 'NewPass123!',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Mot de passe modifié avec succès')
        self.assertEqual(response.data['user']['must_change_password'], False)

        self.client_profile.refresh_from_db()
        self.user.refresh_from_db()
        self.assertFalse(self.client_profile.must_change_password)
        self.assertTrue(self.user.check_password('NewPass123!'))

        me_response = self.client.get('/api/notifications/unread-count/')
        self.assertNotEqual(me_response.status_code, 401)

    def test_change_password_rejects_wrong_temporary_password(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access}')

        response = self.client.post(
            '/api/auth/change-password/',
            {
                'old_password': 'WrongPass!',
                'new_password': 'NewPass123!',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 400)
        self.client_profile.refresh_from_db()
        self.assertTrue(self.client_profile.must_change_password)
