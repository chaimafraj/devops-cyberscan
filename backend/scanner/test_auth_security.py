from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import path
from rest_framework.test import APITestCase
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken

from . import auth_views, client_views


urlpatterns = [
    path('api/auth/register/', auth_views.register_view),
    path('api/auth/logout/', auth_views.logout_view),
    path('api/clients/', client_views.clients_list),
]

User = get_user_model()


@override_settings(ROOT_URLCONF=__name__)
class AuthSecurityApiTests(APITestCase):
    def test_non_admin_cannot_access_clients(self):
        user = User.objects.create_user(
            username='analyst', email='analyst@example.com',
            password='StrongPass123!', role='analyst',
        )
        self.client.force_authenticate(user=user)

        response = self.client.get('/api/clients/')

        self.assertEqual(response.status_code, 403)

    def test_public_registration_persists_requested_role(self):
        response = self.client.post('/api/auth/register/', {
            'username': 'newanalyst',
            'email': 'newanalyst@example.com',
            'password': 'StrongPass123!',
            'role': 'analyst',
        }, format='json')

        self.assertEqual(response.status_code, 201)
        user = User.objects.get(username='newanalyst')
        self.assertEqual(user.role, 'analyst')
        self.assertTrue(user.check_password('StrongPass123!'))
        self.assertEqual(response.data['user']['role'], 'analyst')
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_logout_blacklists_refresh_and_reports_reuse(self):
        user = User.objects.create_user(
            username='logoutuser', email='logout@example.com',
            password='StrongPass123!', role='viewer',
        )
        refresh = RefreshToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        first = self.client.post(
            '/api/auth/logout/', {'refresh': str(refresh)}, format='json'
        )
        second = self.client.post(
            '/api/auth/logout/', {'refresh': str(refresh)}, format='json'
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 400)
        self.assertTrue(
            BlacklistedToken.objects.filter(token__jti=refresh['jti']).exists()
        )
