"""Permissions DRF métier CyberScan."""
from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """
    Accès réservé aux utilisateurs authentifiés avec role == 'admin'.

    À utiliser sur les endpoints d'administration (ex. /api/clients/).
    Ne pas se reposer sur le frontend pour masquer ces routes.
    """

    message = 'Accès réservé aux administrateurs.'

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and getattr(user, 'role', None) == 'admin'
        )
