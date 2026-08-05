import logging
from dataclasses import asdict, dataclass
from typing import Any

from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ApiError:
    code: str
    message: str
    details: Any = None

    def to_dict(self):
        return {'error': {'code': self.code, 'message': self.message, 'details': self.details}}


def api_error_response(code, message, status_code, details=None):
    return Response(ApiError(code, message, details).to_dict(), status=status_code)


def _code_for_status(status_code):
    codes = {400: 'BAD_REQUEST', 401: 'UNAUTHENTICATED', 403: 'FORBIDDEN',
             404: 'NOT_FOUND', 405: 'METHOD_NOT_ALLOWED', 409: 'CONFLICT',
             429: 'THROTTLED', 500: 'INTERNAL_ERROR', 503: 'SERVICE_UNAVAILABLE'}
    return codes.get(status_code, f'HTTP_{status_code}')


def _normalize(payload, status_code):
    if isinstance(payload, dict) and isinstance(payload.get('error'), dict):
        if {'code', 'message'} <= payload['error'].keys():
            return payload
    message = payload.get('error') or payload.get('detail') if isinstance(payload, dict) else None
    if not isinstance(message, str):
        message = 'La requete a echoue.' if status_code < 500 else 'Erreur interne du serveur.'
    return ApiError(_code_for_status(status_code), message, payload).to_dict()


def api_exception_handler(exc, context):
    response = drf_exception_handler(exc, context)
    if response is None:
        logger.exception('Erreur API non geree', exc_info=exc)
        return api_error_response('INTERNAL_ERROR', 'Erreur interne du serveur.', 500)
    response.data = _normalize(response.data, response.status_code)
    return response


class ApiErrorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if isinstance(response, Response) and response.status_code >= 400:
            response.data = _normalize(response.data, response.status_code)
        return response
