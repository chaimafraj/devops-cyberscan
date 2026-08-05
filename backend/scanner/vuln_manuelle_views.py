from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Scan, VulnerabiliteManuelle, Client
from .serializers import VulnerabiliteManuelleSerializer


# Templates par type — auto-fill cote frontend, mais on garde une reference cote backend aussi
TEMPLATES = {
    'idor': {
        'description': "IDOR (Insecure Direct Object Reference) permet à un utilisateur non autorisé d'accéder à des ressources appartenant à d'autres utilisateurs en modifiant un identifiant dans une requête.",
        'technical_business_risks': "Atteinte à la confidentialité des données, non-conformité réglementaire (RGPD), perte de confiance client.",
        'recommandation': "Implémenter un contrôle d'accès strict basé sur les objets. Utiliser des identifiants non prévisibles (UUID). Validation serveur obligatoire.",
    },
    'lfi': {
        'description': "Le LFI (Local File Inclusion) permet à un attaquant d'inclure des fichiers du serveur en manipulant les paramètres d'entrée.",
        'technical_business_risks': "Accès non autorisé à des fichiers sensibles, possibilité d'escalade vers exécution de commandes système.",
        'recommandation': "Valider et filtrer strictement les chemins de fichiers. Utiliser une liste blanche de fichiers autorisés.",
    },
    'xss': {
        'description': "Cross-Site Scripting permet l'injection de scripts malveillants exécutés dans le navigateur des victimes.",
        'technical_business_risks': "Vol de sessions, défacement, phishing via le site légitime.",
        'recommandation': "Échapper systématiquement les entrées utilisateur. Mettre en place une Content Security Policy (CSP).",
    },
    'sqli': {
        'description': "Injection SQL permettant de manipuler les requêtes à la base de données.",
        'technical_business_risks': "Fuite ou corruption de la base de données, contournement d'authentification.",
        'recommandation': "Utiliser des requêtes préparées (paramétrées). Ne jamais concaténer les entrées utilisateur dans les requêtes SQL.",
    },
    'csrf': {
        'description': "Cross-Site Request Forgery permet de faire exécuter des actions non désirées par un utilisateur authentifié.",
        'technical_business_risks': "Actions non autorisées effectuées au nom de la victime.",
        'recommandation': "Implémenter des tokens CSRF sur toutes les actions sensibles.",
    },
    'broken_auth': {
        'description': "Mécanisme d'authentification ou de gestion de session mal implémenté.",
        'technical_business_risks': "Usurpation d'identité, accès non autorisé aux comptes utilisateurs.",
        'recommandation': "Renforcer la politique de mots de passe, implémenter le MFA, sécuriser la gestion des sessions.",
    },
    'sensitive_data': {
        'description': "Exposition de données sensibles (mots de passe, tokens, informations personnelles) sans protection adéquate.",
        'technical_business_risks': "Fuite de données confidentielles, non-conformité RGPD.",
        'recommandation': "Chiffrer les données sensibles au repos et en transit. Ne jamais exposer de données sensibles dans les réponses API.",
    },
    'spam': {
        'description': "Envoi massif et non sollicité de messages (SMS/email) via une interface exposée sans contrôle suffisant.",
        'technical_business_risks': "Atteinte à la réputation, coûts financiers, responsabilité légale.",
        'recommandation': "Implémenter une authentification forte et un rate limiting sur les interfaces d'envoi.",
    },
    'autre': {
        'description': '',
        'technical_business_risks': '',
        'recommandation': '',
    },
}


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def vuln_templates(request):
    return Response(TEMPLATES)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def vuln_manuelle_list(request, scan_id):
    user = request.user

    try:
        scan = Scan.objects.get(pk=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan introuvable'}, status=404)

    # Verifier acces (admin voit tout, client bark son scan)
    if user.role != 'admin':
        try:
            client = user.client_profile
        except Client.DoesNotExist:
            client = None
        if scan.client_id != (client.id if client else None):
            return Response({'error': 'Accès refusé'}, status=403)

    if request.method == 'GET':
        vulns = scan.vulnerabilites_manuelles.all().order_by('-date_ajout')
        serializer = VulnerabiliteManuelleSerializer(vulns, many=True)
        return Response(serializer.data)

    if request.method == 'POST':
        data = request.data.copy()
        data['scan'] = scan.id
        serializer = VulnerabiliteManuelleSerializer(data=data)
        if serializer.is_valid():
            serializer.save(ajoutee_par=user)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def vuln_manuelle_detail(request, pk):
    user = request.user
    try:
        vuln = VulnerabiliteManuelle.objects.get(pk=pk)
    except VulnerabiliteManuelle.DoesNotExist:
        return Response({'error': 'Vulnérabilité introuvable'}, status=404)

    if user.role != 'admin':
        try:
            client = user.client_profile
        except Client.DoesNotExist:
            client = None
        if vuln.scan.client_id != (client.id if client else None):
            return Response({'error': 'Accès refusé'}, status=403)

    vuln.delete()
    return Response({'message': 'Vulnérabilité supprimée'})