"""API REST sÃ©curisÃ©e et conversationnelle du chatbot RAG CyberScan."""
from __future__ import annotations

import logging
import re
import threading
import time
import uuid

from django.db.models import Q
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from .models import ChatConversation, ChatMessage, Client, Scan
from .serializers import ChatbotRequestSerializer, ChatbotResponseSerializer

logger = logging.getLogger(__name__)
_chatbot = None
_chatbot_lock = threading.Lock()
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
_REPORT_TERMS = ('rapport complet', 'rapport d’analyse', "rapport d'analyse", 'présente le scan')
_DOMAIN_RE = re.compile(r'(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', re.IGNORECASE)
_FOLLOWUP_REFERENCE_RE = re.compile(
    r'(?i)(?:'
    r'\bcette\s+(?:cve|vuln[eé]rabilit[eé]|faille|menace)\b|'
    r'\bce\s+probl[eè]me\b|'
    r'\bla\s+corriger\b|'
    r'\bla\s+r[eé]soudre\b|'
    r'\bcomment\s+(?:la|le)\s+(?:corriger|r[eé]soudre|fixer)\b|'
    r'\bpourquoi\s+(?:est[- ]elle|elle\s+est|cette)\b|'
    r'\b(?:quel|quelle)\s+est\s+(?:son|sa)\b|'
    r'\bquelle\s+recommandation\b|'
    r'\bson\s+impact\b|'
    r'\bsa\s+(?:s[eé]v[eé]rit[eé]|recommandation|description|gravit[eé]|note|score)\b|'
    r'\bet\s+(?:elle|cette)\b|'
    r'\belle\b(?:\s*,\s*|\s+)(?:elle\s+)?(?:est\s+)?(?:dangereuse|critique|prioritaire|grave)\b|'
    r'\b(?:explique|expliques|d[eé]taille|d[eé]cris|d[eé]crire)\b.{0,40}\b(?:cette|elle|la\s+cve)\b|'
    r'\b(?:corriger|r[eé]soudre|fixer)\s+(?:cette|ce)\b'
    r')'
)
_UNRESOLVED_CVE_MESSAGE = (
    'Je ne peux pas déterminer quelle CVE vous désignez. '
    'Veuillez préciser son identifiant, par exemple CVE-2025-XXXX.'
)


class ChatbotRateThrottle(UserRateThrottle):
    rate = '10/min'


def _get_chatbot():
    global _chatbot
    if _chatbot is None:
        with _chatbot_lock:
            if _chatbot is None:
                from .ai_module.chatbot import ChatbotRAG
                _chatbot = ChatbotRAG()
    return _chatbot


def _visible_scans(user):
    queryset = Scan.objects.select_related('client', 'created_by').prefetch_related(
        'cves', 'vulnerabilites_manuelles'
    )
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


def _select_scan(user, scan_id=None):
    queryset = _visible_scans(user)
    if scan_id is not None:
        return queryset.filter(pk=scan_id).first(), 'scan'
    return queryset.order_by('-date_scan', '-id').first(), 'latest_scan'


def _select_conversation(user, scan, conversation_id=None, new_conversation=False):
    if new_conversation:
        return ChatConversation.objects.create(user=user, scan=scan)
    if conversation_id is not None:
        conversation = ChatConversation.objects.filter(pk=conversation_id, user=user).first()
        if conversation is None or conversation.scan_id != scan.id:
            return None
        return conversation
    if not new_conversation:
        conversation = ChatConversation.objects.filter(user=user, scan=scan).first()
        if conversation is not None:
            return conversation
    return ChatConversation.objects.create(user=user, scan=scan)


def _conversation_history(conversation, limit=12):
    messages = list(conversation.messages.order_by('-id')[:limit])
    messages.reverse()
    return '\n'.join(
        f"{'Utilisateur' if item.role == ChatMessage.Role.USER else 'CyberScan IA'}: {item.content}"
        for item in messages
    )


def _find_cve(facts, cve_id):
    target = (cve_id or '').upper()
    return next((item for item in facts['cves'] if item['id'].upper() == target), None)


def _find_manual_vulnerability(facts, name):
    target = (name or '').casefold()
    return next(
        (item for item in facts['manual_vulnerabilities'] if item['name'].casefold() == target),
        None,
    )


def _is_followup_reference(question):
    return bool(_FOLLOWUP_REFERENCE_RE.search(question or ''))


def _last_finding_from_history(history, facts):
    """Retourne la dernière CVE/vulnérabilité de l'historique présente dans facts."""
    if not history:
        return None

    known_cves = {item['id'].upper() for item in facts['cves']}
    known_vulns = [item['name'] for item in facts['manual_vulnerabilities'] if item.get('name')]

    for line in reversed(history.splitlines()):
        matches = list(_CVE_RE.finditer(line))
        for match in reversed(matches):
            cve_id = match.group(0).upper()
            if cve_id in known_cves:
                return {'type': 'cve', 'id': cve_id}

        line_cf = line.casefold()
        for name in known_vulns:
            if name.casefold() in line_cf:
                return {'type': 'vulnerability', 'name': name}
    return None


def resolve_conversation_target(question, history, facts):
    """Identifie explicitement l'entité (CVE/vuln) visée par la question.

    Priorité :
    1. CVE explicite dans la question (si présente dans facts)
    2. Vulnérabilité manuelle explicite dans la question
    3-5. Référence conversationnelle → dernière entité fiable de l'historique
    6. None si aucune cible fiable
    """
    question = question or ''
    facts = facts or {}

    match = _CVE_RE.search(question)
    if match:
        cve_id = match.group(0).upper()
        if _find_cve(facts, cve_id) is not None:
            return {'type': 'cve', 'id': cve_id}
        return {'type': 'cve', 'id': cve_id, 'missing': True}

    question_cf = question.casefold()
    for item in facts.get('manual_vulnerabilities') or []:
        name = item.get('name') or ''
        if name and name.casefold() in question_cf:
            return {'type': 'vulnerability', 'name': name}

    if not _is_followup_reference(question):
        return None

    target = _last_finding_from_history(history, facts)
    if target is not None:
        return target
    return {'type': 'unresolved'}


def _cve_default_recommendation(cve):
    return cve.get('recommendation') or (
        'Appliquez le correctif officiel du fournisseur puis relancez le scan.'
    )


def _answer_about_cve(question, cve):
    normalized = (question or '').casefold()
    cve_id = cve['id']
    score = cve['score']
    description = cve['description'] or 'Description non fournie par le scan.'
    recommendation = _cve_default_recommendation(cve)
    correction_terms = (
        'corrig', 'correctif', 'corrective', 'remédi', 'remedi',
        'solution', 'recommand', 'résoudre', 'resoudre', 'fixer',
    )
    impact_terms = ('impact', 'danger', 'conséquence', 'consequence', 'effet')
    severity_terms = (
        'sévérité', 'severite', 'gravité', 'gravite', 'score', 'cvss', 'niveau',
    )
    why_terms = ('pourquoi', 'critique', 'prioritaire', 'grave', 'dangereuse', 'dangereux')

    if any(term in normalized for term in correction_terms):
        return (
            f"Pour corriger {cve_id} : {recommendation} "
            "Après correction, relancez le scan pour vérifier que la vulnérabilité n’est plus détectée."
        )
    if any(term in normalized for term in impact_terms):
        return (
            f"Impact de {cve_id} (CVSS {score}/10) : {description} "
            "Les conditions d’exploitation dépendent du composant affecté et des informations de l’éditeur."
        )
    if any(term in normalized for term in severity_terms) and not any(
        term in normalized for term in ('explique', 'expliques', 'détaille', 'detaille')
    ):
        level = (
            'critique' if float(score) >= 9 else
            'élevé' if float(score) >= 7 else
            'moyen' if float(score) >= 4 else
            'faible'
        )
        return (
            f"{cve_id} a un score CVSS de {score}/10, soit un niveau de sévérité {level}."
        )
    if any(term in normalized for term in why_terms):
        return (
            f"{cve_id} est critique car son score CVSS est de {score}/10 et {description} "
            f"Elle est prioritaire en raison de ce niveau de sévérité. "
            f"Correction recommandée : {recommendation}"
        )
    return (
        f"{cve_id} possède un score CVSS de {score}/10. Elle concerne {description} "
        f"Son impact dépend du composant exposé ; le scan ne fournit pas davantage de détails "
        f"exploitables. Elle est prioritaire en raison de son niveau de sévérité. "
        f"Correction : {recommendation}"
    )


def _answer_about_vulnerability(question, vuln):
    normalized = (question or '').casefold()
    name = vuln['name']
    score = vuln['score']
    description = vuln['description'] or 'Description non fournie par le scan.'
    impact = vuln.get('impact') or description
    recommendation = vuln.get('recommendation') or (
        'Appliquez le correctif recommandé puis relancez le scan.'
    )
    correction_terms = (
        'corrig', 'correctif', 'corrective', 'remédi', 'remedi',
        'solution', 'recommand', 'résoudre', 'resoudre', 'fixer',
    )
    impact_terms = ('impact', 'danger', 'conséquence', 'consequence', 'effet')
    severity_terms = ('sévérité', 'severite', 'gravité', 'gravite', 'score', 'cvss', 'niveau')
    why_terms = ('pourquoi', 'critique', 'prioritaire', 'grave', 'dangereuse', 'dangereux')

    if any(term in normalized for term in correction_terms):
        return (
            f"Pour corriger {name} : {recommendation} "
            "Après correction, relancez le scan pour vérifier que la vulnérabilité n’est plus détectée."
        )
    if any(term in normalized for term in impact_terms):
        return f"Impact de {name} (CVSS {score}/10) : {impact}"
    if any(term in normalized for term in severity_terms):
        return f"{name} a un score CVSS de {score}/10 (risque {vuln.get('risk') or 'non précisé'})."
    if any(term in normalized for term in why_terms):
        return (
            f"{name} est prioritaire car son score CVSS est de {score}/10. "
            f"Impact : {impact}"
        )
    return (
        f"{name} possède un score CVSS de {score}/10. "
        f"Description : {description} Impact : {impact} "
        f"Correction : {recommendation}"
    )


def _answer_for_resolved_target(question, target, facts):
    if target is None:
        return None
    if target.get('type') == 'unresolved':
        return _UNRESOLVED_CVE_MESSAGE
    if target.get('type') == 'cve':
        cve_id = target.get('id', '').upper()
        if target.get('missing'):
            return f"{cve_id} n’est pas présente dans les données de ce scan."
        cve = _find_cve(facts, cve_id)
        if cve is None:
            return f"{cve_id} n’est pas présente dans les données de ce scan."
        return _answer_about_cve(question, cve)
    if target.get('type') == 'vulnerability':
        vuln = _find_manual_vulnerability(facts, target.get('name'))
        if vuln is None:
            return _UNRESOLVED_CVE_MESSAGE
        return _answer_about_vulnerability(question, vuln)
    return None


def _targeted_answer(question, facts, ai_answer='', history=''):
    normalized = question.casefold()
    mentioned_domains = {item.lower().removeprefix('www.') for item in _DOMAIN_RE.findall(question)}
    current_domain = (facts['domain'] or '').lower().removeprefix('www.')
    other_domains = sorted(item for item in mentioned_domains if item != current_domain)
    if other_domains:
        return (
            f"Le domaine {other_domains[0]} est différent du scan actuel ({facts['domain']}). "
            f"Voulez-vous lancer un nouveau scan sur {other_domains[0]} ? "
            "Le scan ne sera créé qu’après votre confirmation."
        )

    total = (
        len(facts['cves']) + len(facts['manual_vulnerabilities']) +
        len(facts['zap']) + len(facts['nuclei'])
    )
    if any(term in normalized for term in ('combien de temps', 'quel délai', 'quelle durée', 'temps faut-il', 'délai de correction')):
        high_priority = any(float(item['score']) >= 7 for item in facts['cves'] + facts['manual_vulnerabilities'])
        estimate = (
            "quelques heures à quelques jours pour désactiver les protocoles faibles et valider la configuration, "
            "davantage si une mise à niveau applicative ou une fenêtre de maintenance est nécessaire"
            if high_priority or facts['protocols'] else
            "quelques heures à un ou deux jours selon les validations nécessaires"
        )
        return f"Estimation qualitative : {estimate}. Confirmez-la avec l’équipe responsable du service."

    if 'combien' in normalized and any(term in normalized for term in ('critique', 'sévère', 'severe')):
        critical_count = sum(float(item['score']) >= 9 for item in facts['cves'] + facts['manual_vulnerabilities'])
        critical_count += sum(item['risk'].casefold().startswith('critical') for item in facts['zap'])
        critical_count += sum(item['severity'].casefold() == 'critical' for item in facts['nuclei'])
        return (
            f"{critical_count} vulnérabilité critique (CVSS ≥ 9.0) est enregistrée pour ce scan."
            if critical_count == 1 else
            f"{critical_count} vulnérabilités critiques (CVSS ≥ 9.0) sont enregistrées pour ce scan."
        )

    if any(term in normalized for term in ('combien', 'nombre total', 'nombre de vuln', 'total de vuln')):
        return f"{total} vulnérabilité(s) ou constat(s) distinct(s) sont enregistrés pour ce scan."

    # Score / risque global : ne pas confondre avec "son score" (référence à une CVE).
    asks_global_score = any(
        term in normalized for term in ('score global', 'note globale', 'niveau global', 'risque global')
    ) or (
        any(term in normalized for term in ('score', 'note globale', 'niveau global', 'risque global'))
        and not _is_followup_reference(question)
        and _CVE_RE.search(question) is None
    )
    if asks_global_score:
        from .ai_module.chatbot import _risk_label
        return (
            f"Le score global de {facts['domain']} est de {facts['score']}/10, "
            f"soit un niveau de risque {_risk_label(facts['score'])}."
        )

    # Résolution de contexte conversationnel AVANT le fallback général.
    target = resolve_conversation_target(question, history, facts)
    target_answer = _answer_for_resolved_target(question, target, facts)
    if target_answer is not None:
        return target_answer

    domain = facts['domain'] if re.fullmatch(r'[A-Za-z0-9.-]{1,253}', facts['domain'] or '') else '<domaine-du-scan>'

    if 'poodle' in normalized:
        evidence = ' '.join(
            facts['protocols'] + [item['description'] for item in facts['cves']]
        ).casefold()
        detected = 'poodle' in evidence
        prefix = (
            "POODLE apparaît dans les résultats du scan. " if detected else
            "POODLE n’est pas explicitement identifiée dans les résultats du scan. "
        )
        return (
            prefix +
            "POODLE exploite le remplissage CBC de SSL 3.0, et certaines variantes concernent des implémentations TLS vulnérables, "
            "pour déchiffrer progressivement des données de session. Désactivez SSL 3.0 et TLS 1.0, utilisez TLS 1.2/1.3, "
            f"puis contrôlez avec : nmap --script ssl-enum-ciphers -p 443 {domain}"
        )

    if any(term in normalized for term in ('si je ne corrige', 'si on ne corrige', 'sans correction', 'ne corrige rien')):
        impacts = [item['impact'] for item in facts['manual_vulnerabilities'] if item['impact']]
        if facts['protocols']:
            impacts.append(
                "Protocoles faibles : ils peuvent permettre l’interception, le déchiffrement partiel ou la dégradation de la confidentialité des échanges."
            )
        impacts.extend(
            f"{item['id']} peut rester exploitable : {item['description']}" for item in facts['cves'][:3]
        )
        return '\n'.join(f"- {item}" for item in impacts) if impacts else (
            "Le scan ne contient pas assez de données pour quantifier précisément l’impact d’une absence de correction."
        )


    if 'sweet32' in normalized:
        evidence = ' '.join(
            facts['protocols'] +
            [item['description'] for item in facts['cves']] +
            [item['description'] for item in facts['manual_vulnerabilities']]
        ).casefold()
        detected = 'sweet32' in evidence or '3des' in evidence or 'tripledes' in evidence
        prefix = (
            "Sweet32 ou l’usage de 3DES apparaît dans les résultats de ce scan. "
            if detected else
            "Sweet32 n’est pas explicitement identifiée dans les résultats de ce scan. "
        )
        return (
            prefix +
            "Cette attaque exploite la petite taille de bloc de 64 bits de chiffrements comme 3DES : "
            "sur un volume important de trafic, des collisions peuvent révéler des fragments de données. "
            "Désactivez 3DES et les suites DES-CBC, privilégiez AES-GCM ou ChaCha20-Poly1305, puis vérifiez avec : "
            f"nmap --script ssl-enum-ciphers -p 443 {domain}"
        )
    port_question = bool(re.search(r'\bports?\b|\bssh\b|\bservices?\b', normalized))
    if port_question:
        ports = facts['ports']
        numbered_question = re.sub(r'^\s*\d+\.\s*', '', normalized)
        requested_ports = [int(value) for value in re.findall(r'\b(?:port\s*)?(\d{2,5})\b', numbered_question)]
        if any(term in normalized for term in ('service', 'tournent', 'tourne')):
            if ports:
                return '\n'.join(
                    f"- {item['port']}/{item['transport']} : {item['service']} ({item['state']})"
                    for item in ports
                )
            reason = " car le scan Nmap a dépassé son délai" if facts['port_scan_timed_out'] else ""
            return f"Aucun service réseau n’a été confirmé{reason}. Relancez un scan Nmap complet."

        if requested_ports:
            requested_port = requested_ports[0]
            finding = next((item for item in ports if item['port'] == requested_port), None)
            if finding:
                detail = (
                    f"Le port {requested_port}/{finding['transport']} est confirmé {finding['state']} "
                    f"avec le service {finding['service']}."
                )
                if requested_port == 443 and facts['protocols']:
                    detail += " Sa configuration TLS présente les protocoles faibles suivants : " + ', '.join(facts['protocols']) + '.'
                return detail
            reason = "Le scan Nmap a dépassé son délai, " if facts['port_scan_timed_out'] else "D’après les résultats Nmap disponibles, "
            return reason + f"le port {requested_port} n’est pas confirmé ouvert. Ne concluez pas qu’il est fermé sans relancer le scan."

        if any(term in normalized for term in ('fermer', 'bloquer', 'filtrer')):
            nonessential = [item for item in ports if item['port'] not in {80, 443}]
            if nonessential:
                listed = ', '.join(f"{item['port']}/{item['transport']} ({item['service']})" for item in nonessential)
                return f"Ports à examiner avant fermeture ou filtrage : {listed}. Validez leur utilité métier avant toute action."
            reason = "Le scan Nmap a dépassé son délai et " if facts['port_scan_timed_out'] else ""
            return f"{reason}aucun port non essentiel n’est confirmé ouvert. Relancez Nmap avant de modifier le pare-feu."

        if ports:
            return "Ports ouverts confirmés : " + ', '.join(
                f"{item['port']}/{item['transport']} ({item['service']})" for item in ports
            ) + '.'
        reason = "Le scan Nmap a dépassé son délai ; " if facts['port_scan_timed_out'] else ""
        return f"{reason}aucun port ouvert n’a été confirmé. Relancez un scan Nmap complet pour obtenir une liste fiable."

    if re.search(r'\bcommandes?\b', normalized) or any(term in normalized for term in ('linux', 'sslscan', 'nmap')):
        return '\n'.join([
            f"Commandes de vérification pour {facts['domain']} :",
            f"sslscan {domain}",
            f"nmap --script ssl-enum-ciphers -p 443 {domain}",
            f"openssl s_client -connect {domain}:443 -tls1",
            f"curl -I https://{domain}",
        ])

    tls_question = any(term in normalized for term in ('tls 1.0', 'tls1.0', 'tlsv1.0', 'tls 1.1', 'tls1.1', 'tlsv1.1'))
    correction_question = any(term in normalized for term in ('corrig', 'correctif', 'corrective', 'remédi', 'remedi', 'solution', 'recommand'))
    if tls_question and correction_question:
        detected = ', '.join(facts['protocols']) or 'TLS obsolète'
        return (
            f"Le scan a détecté : {detected}. Désactivez TLS 1.0 et TLS 1.1 sur le serveur, "
            "conservez TLS 1.2 et TLS 1.3, supprimez les suites de chiffrement faibles, "
            f"redémarrez le service puis vérifiez avec : "
            f"nmap --script ssl-enum-ciphers -p 443 {domain}"
        )

    if any(term in normalized for term in ('risque', 'impact', 'danger')):
        details = []
        details.extend(
            f"{item['id']} (CVSS {item['score']}/10) : {item['description']}"
            for item in facts['cves'][:3]
        )
        details.extend(
            f"{item['name']} (CVSS {item['score']}/10) : {item['impact'] or item['description']}"
            for item in facts['manual_vulnerabilities'][:3]
        )
        if facts['protocols']:
            details.append(
                "Protocoles faibles : " + ', '.join(facts['protocols']) +
                ". Ils augmentent le risque d’interception ou de déchiffrement des communications."
            )
        return '\n'.join(details) if details else (
            f"Aucun risque détaillé supplémentaire n’est enregistré pour {facts['domain']}."
        )

    if any(term in normalized for term in ('critique', 'grave', 'prioritaire', 'pourquoi')):
        if facts['cves']:
            item = facts['cves'][0]
            return (
                f"{item['id']} est prioritaire car son score CVSS est de {item['score']}/10. "
                f"{item['description']} Correction recommandée : "
                f"{item['recommendation'] or 'appliquer le correctif officiel du fournisseur puis relancer le scan.'}"
            )
        if facts['manual_vulnerabilities']:
            item = facts['manual_vulnerabilities'][0]
            return (
                f"{item['name']} est prioritaire avec un score CVSS de {item['score']}/10. "
                f"Impact : {item['impact'] or item['description']}"
            )

    if correction_question:
        recommendations = [
            item['recommendation'] for item in
            facts['manual_vulnerabilities'] + facts['cves']
            if item['recommendation']
        ]
        if recommendations:
            return '\n'.join(f"- {item}" for item in recommendations[:5])

    from .ai_module.chatbot import factual_conclusion
    return ai_answer or factual_conclusion(facts)

def _clean_ai_answer(answer, facts):
    from .ai_module.chatbot import clean_text
    cleaned = clean_text(answer, 1200)
    if len(cleaned) < 10:
        return ''
    total = (
        len(facts['protocols']) + len(facts['cves']) +
        len(facts['manual_vulnerabilities']) + len(facts['zap']) + len(facts['nuclei'])
    )
    anchors = [facts['domain'], facts['score'], str(total)]
    anchors.extend(item['id'] for item in facts['cves'])
    anchors.extend(item['name'] for item in facts['manual_vulnerabilities'])
    normalized = cleaned.casefold()
    return cleaned if any(anchor and anchor.casefold() in normalized for anchor in anchors) else ''


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([ChatbotRateThrottle])
def chatbot_ask(request):
    request_id = uuid.uuid4().hex[:12]
    started = time.perf_counter()
    input_serializer = ChatbotRequestSerializer(data=request.data)
    if not input_serializer.is_valid():
        logger.warning('chatbot_validation_failed request_id=%s user_id=%s fields=%s',
                       request_id, request.user.id, sorted(input_serializer.errors))
        return Response(input_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = input_serializer.validated_data
    question = data['question']
    requested_scan_id = data.get('scan_id')
    conversation_id = data.get('conversation_id')
    new_conversation = data.get('new_conversation', False)
    conversation = None

    if conversation_id is not None and requested_scan_id is None and not new_conversation:
        conversation = ChatConversation.objects.select_related('scan').filter(
            pk=conversation_id, user=request.user
        ).first()
        if conversation is None:
            return Response({'error': 'Conversation introuvable ou incompatible avec ce scan.'},
                            status=status.HTTP_404_NOT_FOUND)
        scan = conversation.scan
        context_mode = 'scan'
        if not _visible_scans(request.user).filter(pk=scan.id).exists():
            return Response({'error': 'Accès refusé'}, status=status.HTTP_403_FORBIDDEN)
    else:
        scan, context_mode = _select_scan(request.user, requested_scan_id)
        if scan is None:
            if requested_scan_id is not None and Scan.objects.filter(pk=requested_scan_id).exists():
                return Response({'error': 'Accès refusé'}, status=status.HTTP_403_FORBIDDEN)
            message = 'Scan introuvable' if requested_scan_id is not None else 'Aucun scan disponible.'
            return Response({'error': message}, status=status.HTTP_404_NOT_FOUND)

        conversation = _select_conversation(
            request.user, scan, conversation_id, new_conversation
        )
        if conversation is None:
            return Response({'error': 'Conversation introuvable ou incompatible avec ce scan.'},
                            status=status.HTTP_404_NOT_FOUND)

    from .ai_module.chatbot import (
        build_response_sections, build_scan_context, collect_scan_facts,
        factual_conclusion, render_sections, sanitize_user_visible_text,
    )

    history = _conversation_history(conversation)
    first_message = not conversation.messages.exists()
    ChatMessage.objects.create(
        conversation=conversation, role=ChatMessage.Role.USER, content=question
    )
    context = build_scan_context(scan)
    facts = collect_scan_facts(scan)

    ai_answer = ''
    chatbot = _get_chatbot()
    if getattr(chatbot, 'available', False):
        try:
            ai_answer = _clean_ai_answer(chatbot.answer(question, context, history), facts)
        except Exception as exc:
            logger.error('chatbot_generation_failed request_id=%s scan_id=%s error_type=%s',
                         request_id, scan.id, exc.__class__.__name__)
    else:
        logger.warning('chatbot_model_unavailable request_id=%s scan_id=%s', request_id, scan.id)

    regenerate = data.get('regenerate', False)
    asks_for_report = any(term in question.casefold() for term in _REPORT_TERMS)
    is_report = regenerate or asks_for_report
    sections = None
    if is_report:
        sections = build_response_sections(scan, question, ai_answer or factual_conclusion(facts))
        answer = render_sections(sections)
    else:
        answer = _targeted_answer(question, facts, ai_answer, history=history)

    if sections is not None:
        sections = {
            name: sanitize_user_visible_text(value, 2000) or 'Information indisponible.'
            for name, value in sections.items()
        }
        answer = render_sections(sections)
    else:
        safe_answer = sanitize_user_visible_text(answer, 2000)
        if not safe_answer:
            logger.warning('chatbot_output_blocked_prompt_leak request_id=%s scan_id=%s', request_id, scan.id)
            safe_answer = factual_conclusion(facts)
        answer = safe_answer

    ChatMessage.objects.create(
        conversation=conversation, role=ChatMessage.Role.ASSISTANT,
        content=answer, is_report=is_report,
    )
    conversation.save(update_fields=['updated_at'])

    payload = {
        'answer': answer,
        'question': question,
        'scan_id': scan.id,
        'conversation_id': conversation.id,
        'context_mode': context_mode,
        'is_report': is_report,
    }
    if sections is not None:
        payload['sections'] = sections
    output_serializer = ChatbotResponseSerializer(data=payload)
    if not output_serializer.is_valid():
        logger.error('chatbot_output_invalid request_id=%s fields=%s',
                     request_id, sorted(output_serializer.errors))
        return Response({'error': 'Réponse IA invalide.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elapsed_ms = round((time.perf_counter() - started) * 1000)
    logger.info(
        'chatbot_request_completed request_id=%s user_id=%s scan_id=%s conversation_id=%s '
        'first_message=%s regenerate=%s model_called=%s answer_chars=%d duration_ms=%d',
        request_id, request.user.id, scan.id, conversation.id, first_message,
        regenerate, bool(ai_answer), len(answer), elapsed_ms,
    )
    return Response(output_serializer.validated_data, status=status.HTTP_200_OK)
