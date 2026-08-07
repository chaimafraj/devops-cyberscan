from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import User


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({'error': 'Username et password requis'}, status=400)

    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Identifiants incorrects'}, status=401)

    refresh = RefreshToken.for_user(user)
    return Response({
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
        }
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    role = request.data.get('role', 'viewer')

    if not all([username, email, password]):
        return Response({'error': 'Tous les champs sont requis'}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({'error': "Nom d'utilisateur déjà utilisé"}, status=400)

    if User.objects.filter(email=email).exists():
        return Response({'error': 'Email déjà utilisé'}, status=400)

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        role=role
    )

    refresh = RefreshToken.for_user(user)
    return Response({
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
        }
    }, status=201)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me_view(request):
    user = request.user
    return Response({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        refresh_token = request.data.get('refresh')
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({'message': 'Déconnexion réussie'})
    except Exception:
        return Response({'message': 'Déconnexion réussie'})


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def users_list(request):
    if request.user.role != 'admin':
        return Response({'error': 'Accès refusé'}, status=403)

    if request.method == 'GET':
        users = User.objects.all()
        return Response([{
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'role': u.role,
            'is_active': u.is_active,
        } for u in users])

    if request.method == 'POST':
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role', 'viewer')

        if User.objects.filter(username=username).exists():
            return Response({'error': "Utilisateur déjà existant"}, status=400)

        user = User.objects.create_user(
            username=username, email=email,
            password=password, role=role
        )
        return Response({
            'id': user.id, 'username': user.username,
            'email': user.email, 'role': user.role,
        }, status=201)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def user_detail(request, pk):
    if request.user.role != 'admin':
        return Response({'error': 'Accès refusé'}, status=403)
    try:
        user = User.objects.get(pk=pk)
        user.delete()
        return Response({'message': 'Utilisateur supprimé'})
    except User.DoesNotExist:
        return Response({'error': 'Utilisateur introuvable'}, status=404)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    user = request.user
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')

    if not old_password or not new_password:
        return Response({'error': 'Ancien et nouveau mot de passe requis'}, status=400)

    if not user.check_password(old_password):
        return Response({'error': 'Ancien mot de passe incorrect'}, status=400)

    if len(new_password) < 6:
        return Response({'error': 'Le nouveau mot de passe doit contenir au moins 6 caractères'}, status=400)

    user.set_password(new_password)
    user.save()

    must_change = False
    if hasattr(user, 'client_profile'):
        user.client_profile.must_change_password = False
        user.client_profile.save(update_fields=['must_change_password'])

    return Response({
        'message': 'Mot de passe modifié avec succès',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'must_change_password': must_change,
        },
    })