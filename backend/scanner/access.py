from django.db.models import Q

from .models import Client, Scan


def visible_scans(user):
    queryset = Scan.objects.all()
    if getattr(user, 'role', None) == 'admin':
        return queryset
    try:
        client_id = user.client_profile.id
    except (Client.DoesNotExist, AttributeError):
        client_id = None
    ownership = Q(created_by=user)
    if client_id is not None:
        ownership |= Q(client_id=client_id)
    return queryset.filter(ownership)


def user_can_access_scan(user, scan):
    if getattr(user, 'role', None) == 'admin':
        return True
    if scan.created_by_id == user.id:
        return True
    try:
        return scan.client_id == user.client_profile.id
    except (Client.DoesNotExist, AttributeError):
        return False