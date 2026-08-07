import logging
import secrets
import string

from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.conf import settings
from django.db import transaction
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import User, Client, Site, Scan

logger = logging.getLogger(__name__)


def generate_temp_password(length=10):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def is_admin(user):
    return user.role == 'admin'


# ---------------- CLIENTS ----------------

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def clients_list(request):
    if not is_admin(request.user):
        return Response({'error': 'Accès refusé'}, status=403)

    if request.method == 'GET':
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 10))

        clients = Client.objects.all().order_by('-date_creation')
        paginator = Paginator(clients, page_size)
        page_obj = paginator.get_page(page)

        results = []
        for c in page_obj:
            results.append({
                'id': c.id,
                'nom': c.nom,
                'email': c.email,
                'is_active': c.is_active,
                'must_change_password': c.must_change_password,
                'date_creation': c.date_creation,
                'nb_sites': Scan.objects.filter(client=c).values('domaine').distinct().count(),
            })

        return Response({
            'results': results,
            'count': paginator.count,
            'total_pages': paginator.num_pages,
            'current_page': page,
        })

    if request.method == 'POST':
        nom = request.data.get('nom')
        email = request.data.get('email')
        username = request.data.get('username', '').strip()

        if not nom or not email or not username:
            return Response({'error': 'Nom, username et email requis'}, status=400)

        if Client.objects.filter(email=email).exists():
            return Response({'error': 'Un client avec cet email existe déjà'}, status=400)

        if User.objects.filter(username=username).exists():
            return Response({'error': "Ce nom d'utilisateur est déjà utilisé"}, status=400)

        temp_password = generate_temp_password()

        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=temp_password,
                    role='client',
                )

                client = Client.objects.create(
                    nom=nom,
                    email=email,
                    user=user,
                    must_change_password=True,
                    created_by=request.user,
                )

                email_sent = send_mail(
                    subject='Vos identifiants CyberScan',
                    message=(
                        f"Bonjour {nom},\n\n"
                        f"Votre compte CyberScan a été créé.\n\n"
                        f"Nom d'utilisateur : {username}\n"
                        f"Mot de passe temporaire : {temp_password}\n\n"
                        f"Merci de vous connecter et de changer votre mot de passe "
                        f"dès votre première connexion.\n\n"
                        f"L'équipe CyberScan"
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
                if email_sent != 1:
                    raise RuntimeError("Le serveur SMTP n'a accepté aucun message")
        except Exception:
            logger.exception(
                'client_invitation_email_failed username=%s recipient=%s',
                username,
                email,
            )
            return Response({
                'error': (
                    "L'e-mail d'identifiants n'a pas pu être envoyé. "
                    "Le client n'a pas été créé ; vérifiez la configuration SMTP et réessayez."
                ),
            }, status=502)

        return Response({
            'id': client.id,
            'nom': client.nom,
            'email': client.email,
            'email_status': 'envoyé',
        }, status=201)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def client_detail(request, pk):
    if not is_admin(request.user):
        return Response({'error': 'Accès refusé'}, status=403)

    try:
        client = Client.objects.get(pk=pk)
    except Client.DoesNotExist:
        return Response({'error': 'Client introuvable'}, status=404)

    if client.user:
        client.user.delete()  # cascade delete client + sites
    else:
        client.delete()

    return Response({'message': 'Client supprimé'})


# ---------------- SITES (côté client) ----------------

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def my_sites(request):
    try:
        client = request.user.client_profile
    except Client.DoesNotExist:
        return Response({'error': "Aucun profil client associé"}, status=403)

    if request.method == 'GET':
        sites = client.sites.all().order_by('-date_ajout')
        return Response([
            {'id': s.id, 'domaine': s.domaine, 'date_ajout': s.date_ajout}
            for s in sites
        ])

    if request.method == 'POST':
        domaine = request.data.get('domaine')
        if not domaine:
            return Response({'error': 'Domaine requis'}, status=400)

        site = Site.objects.create(client=client, domaine=domaine)
        return Response({'id': site.id, 'domaine': site.domaine}, status=201)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def site_detail(request, pk):
    try:
        client = request.user.client_profile
    except Client.DoesNotExist:
        return Response({'error': "Aucun profil client associé"}, status=403)

    try:
        site = Site.objects.get(pk=pk, client=client)
    except Site.DoesNotExist:
        return Response({'error': 'Site introuvable'}, status=404)

    site.delete()
    return Response({'message': 'Site supprimé'})