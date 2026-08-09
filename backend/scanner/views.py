import os
import re
import time
from functools import lru_cache
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from django.db.models import Count, Avg
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import Scan, Client
from .scan_cancellation import ScanCancelled
from .serializers import ScanDetailSerializer, ScanSerializer
from .ssh_scanner import (
    parse_target, run_nmap, run_nuclei, run_openssl, run_ssllabs,
    run_sslscan, run_whatweb, run_zap,
)
from .nvd_service import enrich_scan_with_nvd
from .cve_data import normalize_cve_id, normalize_cve_record, nvd_url_for
from .scan_persistence import build_stored_results, replace_scan_cves
from .ssl_certificate import extract_certificate
from .risk_policy import level_from_score, priority_from_score
from .report_data import (
    extract_cipher_suites, extract_ip_address, extract_ports, extract_tls_versions,
    extract_web_server, fetch_network_metadata,
)

from .ai_module.risk_scorer import RiskScorer
from .ai_module.recommender import VulnRecommender

scorer_rf = RiskScorer()
@lru_cache(maxsize=1)
def _get_recommender():
    # Charge Flan-T5 uniquement lorsqu'une recommandation doit être générée.
    return VulnRecommender()


# =========================================================================
# 0. AUTHENTICATION : REGISTER USER
# =========================================================================
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    role = request.data.get('role', 'User')

    if not username or not password:
        return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Nom d’utilisateur déjà existant.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, email=email, password=password)

    return Response({'message': 'Utilisateur créé avec succès !'}, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    from .dashboard_service import build_dashboard_payload

    response = Response(build_dashboard_payload(request.user), status=status.HTTP_200_OK)
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

# =========================================================================
# 2. INTERNAL UTILS : PARSER MTA3 EL DATA
# =========================================================================
def parse_sslscan(raw_output):
    protocols = []
    vulnerabilities = []

    for line in raw_output.split('\n'):
        if 'TLSv1.0' in line and 'enabled' in line:
            protocols.append({'name': 'TLSv1.0', 'status': 'vulnerable'})
            vulnerabilities.append('TLSv1.0')

        if 'TLSv1.1' in line and 'enabled' in line:
            protocols.append({'name': 'TLSv1.1', 'status': 'obsolete'})
            vulnerabilities.append('TLSv1.1')

        if 'TLSv1.2' in line and 'enabled' in line:
            protocols.append({'name': 'TLSv1.2', 'status': 'secure'})

        if 'TLSv1.3' in line and 'enabled' in line:
            protocols.append({'name': 'TLSv1.3', 'status': 'secure'})

        if '3DES' in line or 'RC4' in line:
            vulnerabilities.append('WEAK_CIPHER')

    return protocols, list(set(vulnerabilities))


# =========================================================================
# 3. PIPELINE DE SCAN CRÉATION (SINGLE OU MULTI-SITE)
# =========================================================================
def scan_single_site(target, is_prod=True, has_money=False, options=None, cancel_check=None):
    scan_started = time.monotonic()
    options = options or {}
    tool_executions = {}

    def run_measured(tool_name, operation, *args, **kwargs):
        started_at = timezone.now()
        started_monotonic = time.monotonic()
        succeeded = False
        try:
            result = operation(*args, **kwargs)
            succeeded = not isinstance(result, dict) or result.get('success', True) is not False
            return result
        finally:
            completed_at = timezone.now()
            tool_executions[tool_name] = {
                'started_at': started_at.isoformat(),
                'completed_at': completed_at.isoformat(),
                'duration_seconds': round(time.monotonic() - started_monotonic, 3),
                'success': succeeded,
            }

    def ensure_not_cancelled():
        if cancel_check is None:
            return
        ensure = getattr(cancel_check, 'ensure_not_cancelled', None)
        if ensure is not None:
            ensure(force=True)
        elif cancel_check():
            raise ScanCancelled('Scan annulé')

    ensure_not_cancelled()
    # La cible peut être un domaine, une IP, ou un format "host:port".
    # Si un port est présent, il remplace le port 443 par défaut des outils.
    host, port = parse_target(target)
    sslscan_result = run_measured(
        'sslscan', run_sslscan, host, port, cancel_check=cancel_check,
    )
    ensure_not_cancelled()

    nmap_result = run_measured('nmap', run_nmap, host, port)
    ensure_not_cancelled()
    openssl_result = run_measured('openssl', run_openssl, host, port)
    ensure_not_cancelled()
    whatweb_result = run_measured('whatweb', run_whatweb, host, port)
    ensure_not_cancelled()
    ssllabs_result = run_measured('ssllabs', run_ssllabs, host)
    ensure_not_cancelled()

    # ─── 🔎 API NVD (optionnelle via options={"nvd": true}) ───
    # WhatWeb tourne toujours en amont (NVD en dépend), mais l'appel NVD
    # lui-même ne s'exécute que si options["nvd"] est True. On enrichit à
    # partir des technologies WhatWeb, complétées par les versions de produits
    # repérées dans les sorties brutes Nmap / OpenSSL.
    nvd_result = {'success': True, 'requested': False, 'errors': [], 'cves': []}
    if options.get("nvd", False) == True:
        nvd_result = run_measured(
            'nvd',
            enrich_scan_with_nvd,
            whatweb_result=whatweb_result,
            nmap_raw=nmap_result.get('raw', ''),
            openssl_raw=openssl_result.get('raw', ''),
        )
        nvd_result['requested'] = True
        ensure_not_cancelled()
    # Nuclei analyse l'URL uniquement lorsque sa case est cochée. Le drapeau
    # serveur permet encore de le couper globalement sans modifier le frontend.
    nuclei_requested = bool(options.get('nuclei', False))
    nuclei_result = {
        'success': False,
        'error': None,
        'findings': [],
        'raw': '',
    }
    if nuclei_requested:
        if settings.NUCLEI_ENABLED:
            nuclei_result = run_measured(
                'nuclei', run_nuclei, host, port, cancel_check=cancel_check,
            )
            ensure_not_cancelled()
        else:
            nuclei_result['error'] = 'Nuclei désactivé sur le serveur'
    protocols, vulnerabilities = parse_sslscan(sslscan_result['raw'])
    source_results = {
        'sslscan': sslscan_result.get('raw', ''), 'openssl': openssl_result.get('raw', ''),
        'nmap': nmap_result.get('raw', ''), 'whatweb': whatweb_result, 'protocols': protocols,
    }
    protocols = extract_tls_versions(source_results)
    certificate = extract_certificate(sslscan_result.get('raw', ''), openssl_result.get('raw', ''))
    cipher_suites = extract_cipher_suites(source_results)
    ports = extract_ports(source_results)
    ip_address = extract_ip_address(source_results)
    network_metadata = fetch_network_metadata(ip_address) if options.get('network_metadata', True) else {'ip_address': ip_address}
    web_server = extract_web_server(source_results)
    has_weak_cipher = 'WEAK_CIPHER' in vulnerabilities

    nuclei_findings = nuclei_result.get('findings', []) if nuclei_result.get('success') else []

    # ─── 🕷️ OWASP ZAP Baseline (automatique) ───
    # ZAP est lancé automatiquement après le scan SSL, sauf désactivation
    # explicite via options={"zap": false}.
    zap_result = {'success': False, 'findings': [], 'raw': '', 'error': 'ZAP désactivé'}
    if options.get("zap", True):
        zap_result = run_measured(
            'zap', run_zap, host, port=port, cancel_check=cancel_check,
        )

    zap_findings = zap_result.get('findings', []) if zap_result.get('success') else []
    core_results = {
        'sslscan': sslscan_result,
        'nmap': nmap_result,
        'openssl': openssl_result,
        'whatweb': whatweb_result,
        'ssllabs': ssllabs_result,
    }
    if nuclei_requested:
        core_results['nuclei'] = nuclei_result
    scanner_errors = {
        name: result.get('error') or 'Échec sans détail'
        for name, result in core_results.items()
        if result.get('success') is False
    }
    scan_has_evidence = any(
        result.get('success') is True for result in core_results.values()
    )
    score_ia = scorer_rf.calculate_scan_score(
        security_signals=vulnerabilities,
        has_weak_cipher=has_weak_cipher,
        zap_findings=zap_findings,
        nvd_cves=nvd_result.get('cves', []),
        nmap_raw=nmap_result.get('raw', ''),
        ssllabs_result=ssllabs_result,
        nuclei_findings=nuclei_findings,
        is_prod=is_prod,
        has_money=has_money,
    )
    risk_decision = {
        'score': score_ia, 'level': level_from_score(score_ia),
        'priority': priority_from_score(score_ia),
        'context': {'is_production': bool(is_prod), 'has_financial_data': bool(has_money)},
    }
    # CVE déterminées exclusivement à partir des preuves techniques.
    # TLS 1.0 reste un constat de configuration : ce signal ne prouve pas
    # CVE-2014-3566, qui concerne SSLv3.
    cves_data = []
    sslscan_raw = sslscan_result.get('raw', '')
    if re.search(r'(?i)(?:3DES|DES-CBC3)', sslscan_raw):
        cve_id = 'CVE-2016-2183'
        description = (
            'Une suite Triple-DES acceptée par le serveur utilise des blocs de '
            '64 bits et correspond à la vulnérabilité SWEET32.'
        )
        try:
            recommendation = _get_recommender().generate_remediation(cve_id, description)
        except Exception:
            recommendation = (
                'Désactiver toutes les suites Triple-DES et conserver uniquement '
                'des suites AEAD modernes telles que AES-GCM ou ChaCha20-Poly1305.'
            )
        cves_data.append({
            'cve_id': cve_id,
            'description': description,
            'cvss_score': 7.5,
            'produit_concerne': 'Suites TLS Triple-DES acceptées',
            'lien_nvd': nvd_url_for(cve_id),
            'recommandation_ia': recommendation,
        })

    existing_cve_ids = {item['cve_id'] for item in cves_data}
    for raw_cve in nvd_result['cves']:
        nvd_cve = normalize_cve_record(raw_cve)
        if nvd_cve is None or nvd_cve['cve_id'] in existing_cve_ids:
            continue
        try:
            recommendation = _get_recommender().generate_remediation(
                nvd_cve['cve_id'], nvd_cve['description']
            )
        except Exception:
            recommendation = (
                f"Mettre à jour {nvd_cve['produit_concerne']} vers une version corrigée "
                f"et consulter l'avis NVD pour {nvd_cve['cve_id']}."
            )
        nvd_cve['recommandation_ia'] = recommendation
        nvd_cve['recommendation'] = recommendation
        cves_data.append(nvd_cve)
        existing_cve_ids.add(nvd_cve['cve_id'])

    # Un template Nuclei générique reste une vulnérabilité Nuclei. Il devient
    # une CVE uniquement si son identifiant respecte le format CVE officiel.
    for finding in nuclei_findings:
        cve_id = normalize_cve_id(finding.get('template_id'))
        severity = str(finding.get('severity') or '').lower()
        if not cve_id or severity not in ('critical', 'high') or cve_id in existing_cve_ids:
            continue
        product = str(finding.get('name') or '').strip()
        recommendation = (
            f"Vulnérabilité détectée sur {finding.get('matched_at', target)}. "
            f"Consulter la fiche NVD et la documentation du template {cve_id}."
        )
        cves_data.append({
            'cve_id': cve_id,
            'description': product,
            'cvss_score': 9.0 if severity == 'critical' else 7.0,
            'produit_concerne': product,
            'lien_nvd': nvd_url_for(cve_id),
            'recommandation_ia': recommendation,
        })
        existing_cve_ids.add(cve_id)
    return {
        'domaine': target,
        'success': scan_has_evidence,
        'error': None if scan_has_evidence else '; '.join(scanner_errors.values()),
        'scanner_errors': scanner_errors,
        'score_risque_ia': score_ia,
        'risk_decision': risk_decision,
        'protocols': protocols,
        'vulnerabilities': vulnerabilities,
        'cves': cves_data,
        'sslscan_raw': sslscan_result['raw'],
        'nmap_raw': nmap_result.get('raw', ''),
        'openssl_raw': openssl_result.get('raw', ''),
        'certificate': certificate,
        'cipher_suites': cipher_suites,
        'ports': ports,
        'ip_address': ip_address,
        'network_metadata': network_metadata,
        'web_server': web_server,
        'scan_duration_seconds': round(time.monotonic() - scan_started, 3),
        'tool_executions': tool_executions,
        'nuclei_findings': nuclei_findings,
        'nuclei_raw': nuclei_result.get('raw', ''),
        'nuclei_requested': nuclei_requested,
        'nuclei_success': nuclei_result.get('success', False),
        'nuclei_error': nuclei_result.get('error'),
        'zap_findings': zap_findings,
        'zap_raw': zap_result.get('raw', ''),
        'zap_success': zap_result.get('success', False),
        'zap_error': zap_result.get('error'),
        'whatweb': whatweb_result,
        'ssllabs': ssllabs_result,
        'nvd': {
            'success': nvd_result['success'],
            'requested': nvd_result.get('requested', False),
            'errors': nvd_result['errors'],
            'cves_count': len(nvd_result['cves']),
        },
        # Liste détaillée des CVE NVD (cve_id, cvss_score, severity, description,
        # published_date) sauvegardée dans resultats_ssl["nvd_cves"].
        'nvd_cves': nvd_result['cves'],
    }


# =========================================================================
# 4. MAIN ENDPOINT : LIST & ACTIONS (GET / POST)
# =========================================================================
@api_view(['GET'])
def test_api(request):
    return Response({"message": "API Scanner is running!"}, status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def scans_list(request):
    user = request.user

    if request.method == 'POST':
        from .scan_submission import submit_scans
        return submit_scans(request)

    if user.role == 'admin':
        base_qs = Scan.objects.all()
    else:
        try:
            client = user.client_profile
        except Client.DoesNotExist:
            client = None
        base_qs = Scan.objects.filter(client=client) if client else Scan.objects.none()

    if request.method == 'GET':
        scans = base_qs.order_by('-date_scan')
        search = request.GET.get('search', '')
        risk = request.GET.get('risk', '').upper()

        try:
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 5))
        except ValueError:
            return Response({'error': 'page et page_size doivent être des nombres'}, status=status.HTTP_400_BAD_REQUEST)

        page = max(page, 1)
        page_size = max(page_size, 1)

        if search:
            scans = scans.filter(domaine__icontains=search)

        if risk == 'HIGH':
            scans = scans.filter(score_risque_ia__gte=7)
        elif risk == 'MEDIUM':
            scans = scans.filter(score_risque_ia__gte=4, score_risque_ia__lt=7)
        elif risk == 'LOW':
            scans = scans.filter(score_risque_ia__lt=4)

        total = scans.count()
        total_pages = max(1, (total + page_size - 1) // page_size)

        start = (page - 1) * page_size
        end = start + page_size

        serializer = ScanSerializer(scans[start:end], many=True)

        return Response({
            'results': serializer.data,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': total_pages,
        }, status=status.HTTP_200_OK)

    if request.method == 'POST':
        urls = request.data.get('urls')
        single_url = request.data.get('url')
        email_to = request.data.get('email')

        is_prod = request.data.get('is_production', True)
        has_money = request.data.get('has_financial_data', False)
        options = request.data.get('options', {})

        target_list = urls if urls else ([single_url] if single_url else [])
        if not target_list:
            return Response({'error': 'Aucune URL fournie'}, status=status.HTTP_400_BAD_REQUEST)

        client_for_scan = None
        if user.role != 'admin':
            try:
                client_for_scan = user.client_profile
            except Client.DoesNotExist:
                client_for_scan = None

        rapport_global = []

        for target in target_list:
            target = target.strip()
            if not target:
                continue

            result = scan_single_site(target, is_prod=is_prod, has_money=has_money, options=options)

            if result['success']:
                scan = Scan.objects.create(
                    domaine=target,
                    resultats_ssl=build_stored_results(result),
                    score_risque_ia=result['score_risque_ia'],
                    status=Scan.Status.COMPLETED,
                    completed_at=timezone.now(),
                    created_by=user,
                    client=client_for_scan,
                )

                replace_scan_cves(scan, result.get('cves', []))

                try:
                    from .notification_service import notify_scan_events
                    notify_scan_events(scan)
                except Exception:
                    pass

                # PDF professionnel + email (pièce jointe) — n'altère pas le scan.
                # Appelé après les CVE pour un rapport complet.
                try:
                    from .report_pipeline import finalize_scan_report
                    extra_emails = [email_to] if email_to else None
                    finalize_scan_report(scan, extra_emails=extra_emails)
                except Exception:
                    pass

                rapport_global.append({
                    'id': scan.id,
                    'domaine': target,
                    'success': True,
                    'score_risque_ia': result['score_risque_ia'],
                    'protocols': result['protocols'],
                    'vulnerabilities': result['vulnerabilities'],
                    'whatweb': result.get('whatweb', {
                        'success': False,
                        'technologies': [],
                    }),
                    'ssllabs': result.get('ssllabs', {}),
                    'nvd': result.get('nvd', {
                        'success': True,
                        'errors': [],
                        'cves_count': 0,
                    }),
                    'zap_findings': result.get('zap_findings', []),
                    'zap_success': result.get('zap_success', False),
                    'zap_error': result.get('zap_error'),
                    'cves_count': scan.cves.count()
                })
            else:
                rapport_global.append({
                    'id': None,
                    'domaine': target,
                    'success': False,
                    'error': result['error'],
                    'score_risque_ia': None,
                    'protocols': [],
                    'vulnerabilities': [],
                    'cves_count': 0
                })

        if email_to:
            critiques = [r for r in rapport_global if r.get('score_risque_ia') and r['score_risque_ia'] >= 7]
            try:
                corps = f"Bonjour,\n\nVoici le rapport de sécurité CYBERSCAN pour votre demande de flicage de {len(rapport_global)} site(s):\n\n"
                for r in rapport_global:
                    if r['success']:
                        corps += f"🌐 Site: {r['domaine']} -> Score Risque IA: {r['score_risque_ia']}/10\n"
                    else:
                        corps += f"🌐 Site: {r['domaine']} -> ❌ ÉCHEC DE SCAN ({r['error']})\n"

                if critiques:
                    corps += f"\n🚨 ATTENTION: {len(critiques)} site(s) CRITIQUE(S) détecté(s)! Veuillez vous connecter au tableau de bord Angular pour voir les remédiations en Français."

                send_mail(
                    subject=f'🚨 CYBERSCAN : Rapport Global ({len(rapport_global)} site(s))',
                    message=corps,
                    from_email='noreply@cyberapp.com',
                    recipient_list=[email_to],
                    fail_silently=True,
                )
            except Exception:
                pass

        return Response({'rapport': rapport_global}, status=status.HTTP_201_CREATED)


# =========================================================================
# 5. SCAN DETAIL (GET / PUT / DELETE)
# =========================================================================
@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def scan_detail(request, pk):
    user = request.user
    try:
        scan = Scan.objects.get(pk=pk)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan introuvable'}, status=status.HTTP_404_NOT_FOUND)

    if user.role != 'admin':
        try:
            client = user.client_profile
        except Client.DoesNotExist:
            client = None
        if scan.client_id != (client.id if client else None):
            return Response({'error': 'Accès refusé'}, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'GET':
        serializer = ScanDetailSerializer(scan)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        scan.domaine = request.data.get('domaine', scan.domaine)
        scan.save()
        serializer = ScanSerializer(scan)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'DELETE':
        scan.delete()
        return Response({'message': 'Scan supprimé'}, status=status.HTTP_204_NO_CONTENT)
