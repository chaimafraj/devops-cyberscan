from django.test import override_settings
from django.urls import path
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.test import APITestCase

from .api_errors import ApiError


@api_view(['GET'])
@permission_classes([AllowAny])
def manual_error(_request):
    return Response({'error': 'Valeur incorrecte', 'field': 'target'}, status=400)


@api_view(['GET'])
@permission_classes([AllowAny])
def validation_error(_request):
    raise ValidationError({'target': ['Ce champ est requis.']})


@api_view(['GET'])
@permission_classes([AllowAny])
def unexpected_error(_request):
    raise RuntimeError('secret internal detail')


urlpatterns = [
    path('manual/', manual_error),
    path('validation/', validation_error),
    path('unexpected/', unexpected_error),
]


@override_settings(ROOT_URLCONF=__name__)
class ApiErrorTests(APITestCase):
    def assert_api_error(self, response, code):
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error']['code'], code)
        self.assertIn('message', response.data['error'])
        self.assertIn('details', response.data['error'])

    def test_model_contract(self):
        payload = ApiError('TEST', 'Message', {'field': 'value'}).to_dict()
        self.assertEqual(payload['error']['code'], 'TEST')
        self.assertEqual(payload['error']['details']['field'], 'value')

    def test_manual_error_is_normalized(self):
        response = self.client.get('/manual/')
        self.assertEqual(response.status_code, 400)
        self.assert_api_error(response, 'BAD_REQUEST')
        self.assertEqual(response.data['error']['message'], 'Valeur incorrecte')

    def test_drf_validation_error_is_normalized(self):
        response = self.client.get('/validation/')
        self.assertEqual(response.status_code, 400)
        self.assert_api_error(response, 'BAD_REQUEST')
        self.assertIn('target', response.data['error']['details'])

    def test_unexpected_error_is_hidden_and_normalized(self):
        self.client.raise_request_exception = False
        response = self.client.get('/unexpected/')
        self.assertEqual(response.status_code, 500)
        self.assert_api_error(response, 'INTERNAL_ERROR')
        self.assertNotIn('secret internal detail', str(response.data))
