"""Rapport PDF professionnel CyberScan, construit avec ReportLab."""
from datetime import datetime
from pathlib import Path
import json
import math
import re
import logging

logger = logging.getLogger(__name__)

from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import BaseDocTemplate, Flowable, Frame, Image, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.pdfgen.canvas import Canvas
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie

from .models import Rapport
from .nvd_service import _product_in_description, _versioned_product
from .risk_policy import level_from_score, normalize_score, priority_from_score, recommendation_order
from .report_analysis import build_report_analysis
from .report_data import (
    collect_cves, extract_ports, normalize_results, tool_names_with_results,
)
from .report_generator import (
    COLOR_LIGHT_BG, COLOR_MUTED, COLOR_PRIMARY, COLOR_WHITE, _build_styles,
    _escape, _header_footer, _logo_path, _reports_dir, _section_title,
    risk_level_from_score, security_score_from_risk,
)

TOP_FINDINGS = 15
STANDARD_PORTS = {22, 25, 80, 110, 143, 443}
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _history_url():
    configured_url = str(getattr(settings, 'CYBERSCAN_HISTORY_URL', '') or '').strip()
    if configured_url:
        return configured_url
    site_url = str(getattr(settings, 'CYBERSCAN_SITE_URL', 'http://localhost:4200')).rstrip('/')
    return f'{site_url}/historique'


def _history_qr_block(history_url):
    """Construit le QR d’accès à l’historique pour le bandeau de couverture."""
    qr_size = 25 * mm
    qr = QrCodeWidget(history_url)
    x1, y1, x2, y2 = qr.getBounds()
    qr_width = x2 - x1
    qr_height = y2 - y1
    drawing = Drawing(
        qr_size,
        qr_size,
        transform=[qr_size / qr_width, 0, 0, qr_size / qr_height, 0, 0],
    )
    drawing.add(qr)
    label_style = ParagraphStyle(
        'CSHistoryQrLabel',
        fontName='Helvetica-Bold',
        fontSize=6.5,
        leading=7,
        textColor=COLOR_PRIMARY,
        alignment=TA_CENTER,
        spaceBefore=2,
    )
    block = Table(
        [[drawing], [Paragraph('HISTORIQUE DES SCANS', label_style)]],
        colWidths=[3.2 * cm],
    )
    block.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    return block

def _report_page(canvas, doc):
    _header_footer(canvas, doc)


class NumberedCanvas(Canvas):
    """Ajoute la pagination Page X / total après calcul du document complet."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []
        self._cyberscan_total_pagination = True

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_states = self._saved_page_states
        page_count = len(page_states)
        for state in page_states:
            self.__dict__.update(state)
            self._draw_page_number(page_count)
            Canvas.showPage(self)
        Canvas.save(self)

    def _draw_page_number(self, page_count):
        page_width, _ = A4
        self.saveState()
        self.setFillColor(COLOR_WHITE)
        self.setFont('Helvetica', 8)
        self.drawRightString(
            page_width - 15*mm,
            7*mm,
            f'Page {self.getPageNumber()} / {page_count}',
        )
        self.restoreState()


class CyberScanDocTemplate(BaseDocTemplate):
    """Document ReportLab alimentant automatiquement la table des matières."""

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == 'CSTocHeading':
            self.notify('TOCEntry', (0, flowable.getPlainText(), self.page))

    def build_with_toc(self, flowables):
        self._calc()
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id='normal')
        self.addPageTemplates(PageTemplate(id='CyberScan', frames=frame, onPage=_report_page))
        BaseDocTemplate.multiBuild(self, flowables, canvasmaker=NumberedCanvas)


def _toc_heading(text, styles):
    return Paragraph(_escape(text), ParagraphStyle(
        'CSTocHeading', parent=styles['CSHeading'], fontSize=13,
        textColor=COLOR_PRIMARY, spaceBefore=14, spaceAfter=8,
    ))

class CertificationStamp(Flowable):
    """Cachet CyberScan entièrement vectoriel, ancré au bas de l'espace restant."""

    def __init__(self, scan_id):
        super().__init__()
        self.scan_id = scan_id
        self.width = 78 * mm
        self.minimum_height = 72 * mm

    def wrap(self, available_width, available_height):
        self.available_width = available_width
        self.height = max(self.minimum_height, available_height)
        return available_width, self.height

    def draw(self):
        canvas = self.canv
        center_x = self.available_width - self.width / 2
        caption_y = 4 * mm
        center_y = caption_y + 39 * mm
        outer_radius = 27 * mm
        inner_radius = 23.5 * mm
        stamp_color = colors.HexColor('#1a5276')

        canvas.saveState()
        canvas.setStrokeColor(stamp_color)
        canvas.setFillColor(stamp_color)
        canvas.setLineWidth(1.5)
        canvas.circle(center_x, center_y, outer_radius, stroke=1, fill=0)
        canvas.setLineWidth(0.75)
        canvas.circle(center_x, center_y, inner_radius, stroke=1, fill=0)

        curved_text = 'CYBERSCAN • SECURITY AUDIT PLATFORM •'
        start_angle, end_angle = 150, 30
        radius = 20.5 * mm
        canvas.setFont('Helvetica-Bold', 6.6)
        for index, character in enumerate(curved_text):
            fraction = index / max(1, len(curved_text) - 1)
            angle = start_angle + (end_angle - start_angle) * fraction
            radians = math.radians(angle)
            canvas.saveState()
            canvas.translate(center_x + radius * math.cos(radians), center_y + radius * math.sin(radians))
            canvas.rotate(angle - 90)
            canvas.drawCentredString(0, -2, character)
            canvas.restoreState()

        canvas.setFont('Helvetica-Bold', 12)
        canvas.drawCentredString(center_x, center_y + 2 * mm, 'RAPPORT')
        canvas.drawCentredString(center_x, center_y - 3 * mm, 'CERTIFIÉ')
        canvas.setFont('Helvetica', 8)
        canvas.drawCentredString(center_x, center_y - 9 * mm, f'Scan #{self.scan_id}')
        canvas.setFont('Helvetica', 6.8)
        canvas.drawCentredString(center_x, caption_y + 2.5 * mm, 'Document généré et certifié automatiquement')
        canvas.drawCentredString(center_x, caption_y, 'par la plateforme CyberScan.')
        canvas.restoreState()
REMEDIATION_TEMPLATES = {
    'tls_legacy': {
        'recommendation': 'Désactiver TLS 1.0 et TLS 1.1 et n’autoriser que TLS 1.2/1.3.',
        'steps': [
            'Nginx : définir « ssl_protocols TLSv1.2 TLSv1.3; » dans le bloc serveur.',
            'Apache : définir « SSLProtocol -all +TLSv1.2 +TLSv1.3 » puis recharger le service.',
            'Vérifier avec « openssl s_client -connect <hôte>:443 -tls1 » puis relancer sslscan.',
        ],
    },
    'weak_cipher': {
        'recommendation': 'Retirer 3DES et RC4 de la liste des suites cryptographiques autorisées.',
        'steps': [
            'Nginx : utiliser « ssl_ciphers HIGH:!aNULL:!MD5:!3DES:!RC4; ».',
            'Apache : utiliser « SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4 » puis recharger le service.',
            'Relancer « sslscan <hôte> » et confirmer l’absence de 3DES/RC4.',
        ],
    },
    'obsolete_software': {
        'recommendation': 'Mettre à niveau le composant vers une version maintenue après validation en préproduction.',
        'steps': [
            'Identifier le paquet exact et sauvegarder sa configuration.',
            'Exécuter « apt update && apt install --only-upgrade <paquet> ».',
            'Redémarrer le service, vérifier sa version et rejouer les tests de sécurité.',
        ],
    },
    'exposed_ports': {
        'recommendation': 'Fermer ou filtrer les ports non essentiels et documenter toute exception.',
        'steps': [
            'Confirmer le propriétaire et le besoin métier de chaque service exposé.',
            'Bloquer les ports inutiles avec le pare-feu ou le security group.',
            'Relancer Nmap depuis l’extérieur pour confirmer la fermeture.',
        ],
    },
}


ZAP_REMEDIATION_TEMPLATES = {
    'sub resource integrity': {
        'recommendation': 'Ajouter Subresource Integrity aux ressources JavaScript et CSS chargées depuis un domaine tiers.',
        'steps': [
            'Calculer le hash : « openssl dgst -sha384 -binary fichier.js | openssl base64 -A ».',
            'Script : « <script src="https://cdn.exemple/app.js" integrity="sha384-HASH" crossorigin="anonymous"></script> ».',
            'CSS : « <link rel="stylesheet" href="https://cdn.exemple/app.css" integrity="sha384-HASH" crossorigin="anonymous"> », puis vérifier la console navigateur.',
        ],
    },
    'anti-clickjacking': {
        'recommendation': 'Interdire l’intégration du site dans une frame non autorisée.',
        'steps': ['Nginx : « add_header X-Frame-Options "SAMEORIGIN" always; ».', 'Apache : « Header always set X-Frame-Options "SAMEORIGIN" ».', 'Préférer aussi CSP « frame-ancestors \'self\' » et vérifier avec « curl -I ».'],
    },
    'cookie no httponly': {
        'recommendation': 'Activer HttpOnly, Secure et SameSite sur tous les cookies de session.',
        'steps': ['Application : « Set-Cookie: session=<valeur>; Path=/; Secure; HttpOnly; SameSite=Lax ».', 'Nginx proxy : « proxy_cookie_flags ~ secure httponly samesite=lax; ».', 'Vérifier les attributs avec les outils développeur et un test ZAP.'],
    },
    'samesite': {
        'recommendation': 'Définir SameSite=Lax ou Strict, ainsi que Secure et HttpOnly, sur les cookies sensibles.',
        'steps': ['Émettre « Set-Cookie: session=<valeur>; Secure; HttpOnly; SameSite=Lax ».', 'Réserver SameSite=None aux usages intersites indispensables et l’associer obligatoirement à Secure.', 'Rejouer les parcours d’authentification puis le scan ZAP.'],
    },
    'cross-origin-embedder-policy': {
        'recommendation': 'Isoler les ressources intégrées avec Cross-Origin-Embedder-Policy.',
        'steps': ['Nginx : « add_header Cross-Origin-Embedder-Policy "require-corp" always; ».', 'Apache : « Header always set Cross-Origin-Embedder-Policy "require-corp" ».', 'Vérifier la compatibilité des ressources CORS/CORP puis contrôler avec « curl -I ».'],
    },
    'cross-origin-opener-policy': {
        'recommendation': 'Isoler le contexte de navigation avec Cross-Origin-Opener-Policy.',
        'steps': ['Nginx : « add_header Cross-Origin-Opener-Policy "same-origin" always; ».', 'Apache : « Header always set Cross-Origin-Opener-Policy "same-origin" ».', 'Tester les fenêtres auxiliaires puis vérifier l’en-tête avec « curl -I ».'],
    },
    'cross-origin-resource-policy': {
        'recommendation': 'Limiter le chargement interorigine avec Cross-Origin-Resource-Policy.',
        'steps': ['Nginx : « add_header Cross-Origin-Resource-Policy "same-origin" always; ».', 'Apache : « Header always set Cross-Origin-Resource-Policy "same-origin" ».', 'Utiliser same-site/cross-origin uniquement si nécessaire puis vérifier avec « curl -I ».'],
    },
    'permissions policy': {
        'recommendation': 'Désactiver explicitement les fonctions navigateur non utilisées via Permissions-Policy.',
        'steps': ['Nginx : « add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always; ».', 'Apache : « Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()" ».', 'Adapter les directives aux besoins métier et vérifier avec « curl -I ».'],
    },
}


# Libellés ZAP les plus fréquents, normalisés avant affichage dans les fiches.
ZAP_LABEL_TRANSLATIONS = {
    'Content Security Policy (CSP) Header Not Set': 'En-tête Content-Security-Policy (CSP) absent',
    'Sub Resource Integrity Attribute Missing': 'Attribut Subresource Integrity (SRI) absent',
    'Missing Anti-clickjacking Header': 'En-tête anti-clickjacking absent',
    'X-Frame-Options Header Not Set': 'En-tête X-Frame-Options absent',
    'Cookie No HttpOnly Flag': 'Attribut HttpOnly absent sur un cookie',
    'Cookie No Secure Flag': 'Attribut Secure absent sur un cookie',
    'Cookie with SameSite Attribute None': 'Attribut SameSite du cookie trop permissif',
    'Strict-Transport-Security Header Not Set': 'En-tête HSTS absent',
    'X-Content-Type-Options Header Missing': 'En-tête X-Content-Type-Options absent',
    'Cross-Origin-Embedder-Policy Header Missing or Invalid': 'En-tête Cross-Origin-Embedder-Policy absent ou invalide',
    'Cross-Origin-Opener-Policy Header Missing or Invalid': 'En-tête Cross-Origin-Opener-Policy absent ou invalide',
    'Cross-Origin-Resource-Policy Header Missing or Invalid': 'En-tête Cross-Origin-Resource-Policy absent ou invalide',
    'Permissions Policy Header Not Set': 'En-tête Permissions-Policy absent',
    'CORS Misconfiguration': 'Configuration CORS non sécurisée',
    'CORS Header: Access-Control-Allow-Origin Missing': 'En-tête CORS Access-Control-Allow-Origin absent',
    'Cache-control is not set properly': 'Directive Cache-Control insuffisante',
    'Cacheable Content': 'Contenu sensible potentiellement mis en cache',
    'Information Disclosure - Suspicious Comments': 'Divulgation d’informations dans les commentaires',
    'Server Leaks Version Information via Server HTTP Response Header Field': 'Version du serveur divulguée dans les en-têtes HTTP',
    'Cross-Domain JavaScript Source File Inclusion': 'Inclusion JavaScript depuis un domaine tiers',
}

ZAP_SOLUTION_TRANSLATIONS = {
    'Provide a valid integrity attribute to the tag.': 'Fournir un attribut integrity valide sur la balise.',
    'Ensure that the HttpOnly flag is set for all cookies.': 'Activer l’attribut HttpOnly sur tous les cookies sensibles.',
    'Ensure that the SameSite attribute is set to either lax or ideally strict for all cookies.': 'Définir SameSite=Lax ou SameSite=Strict sur tous les cookies sensibles.',
}

# Les templates ci-dessous remplacent les variantes moins détaillées définies plus haut.
ZAP_REMEDIATION_TEMPLATES.update({
    'sub resource integrity': {
        'recommendation': 'Fournir un attribut integrity valide sur chaque balise script ou link chargée depuis un tiers.',
        'steps': [
            'Nginx : déployer la balise « <script src="/app.js" integrity="sha384-..." crossorigin="anonymous"></script> » dans le fichier HTML servi.',
            'Apache : déployer la même balise SRI dans le document servi par le VirtualHost.',
            'Générer le hash avec « openssl dgst -sha384 -binary fichier.js | openssl base64 -A », puis vérifier dans la console du navigateur.',
        ],
    },
    'anti-clickjacking': {
        'recommendation': 'Interdire l’affichage du site dans une frame non autorisée.',
        'steps': [
            'Nginx : « add_header X-Frame-Options "DENY" always; » ou CSP « frame-ancestors \'none\' ».',
            'Apache : « Header always set X-Frame-Options "DENY" » ou « Header always set Content-Security-Policy "frame-ancestors \'none\'" ».',
            'Vérifier avec « curl -I https://<hôte> » et un test d’intégration dans une iframe.',
        ],
    },
    'cors': {
        'recommendation': 'Limiter CORS aux origines, méthodes et en-têtes strictement nécessaires.',
        'steps': [
            'Nginx : « add_header Access-Control-Allow-Origin "https://app.exemple" always; » sans réflexion dynamique de Origin.',
            'Apache : « Header always set Access-Control-Allow-Origin "https://app.exemple" ».',
            'Vérifier avec « curl -I -H "Origin: https://origine-inconnue.test" https://<hôte> » que l’origine est refusée.',
        ],
    },
    'cache-control': {
        'recommendation': 'Interdire la mise en cache des réponses contenant des données sensibles.',
        'steps': [
            'Nginx : « add_header Cache-Control "no-cache, no-store, must-revalidate, private" always; ».',
            'Apache : « Header always set Cache-Control "no-cache, no-store, must-revalidate, private" ».',
            'Vérifier avec « curl -I https://<hôte>/<ressource-sensible> ».',
        ],
    },
    'cacheable content': {
        'recommendation': 'Interdire la mise en cache des contenus authentifiés ou sensibles.',
        'steps': [
            'Nginx : « add_header Cache-Control "no-cache, no-store, must-revalidate, private" always; ».',
            'Apache : « Header always set Cache-Control "no-cache, no-store, must-revalidate, private" ».',
            'Vérifier avec « curl -I https://<hôte>/<ressource-sensible> » et contrôler l’absence de stockage navigateur/proxy.',
        ],
    },
})


def _translate_zap_label(label):
    return ZAP_LABEL_TRANSLATIONS.get(str(label or ''), str(label or 'Alerte ZAP'))


def _translate_zap_solution(solution):
    text = str(solution or '').strip()
    return ZAP_SOLUTION_TRANSLATIONS.get(text, text if not re.search(r'\b(ensure|provide|set|configure|use|apply)\b', text, re.I) else 'Corriger le paramètre signalé en appliquant le template technique français associé.')
TOOL_DESCRIPTIONS = {
    'SSLScan': 'Inventaire des protocoles et suites cryptographiques TLS.',
    'Nmap': 'Détection des ports ouverts, services et bannières réseau.',
    'OpenSSL': 'Contrôle de la négociation TLS et du certificat présenté.',
    'WhatWeb': 'Identification des technologies et versions web.',
    'Nuclei': 'Recherche par signatures de vulnérabilités connues.',
    'OWASP ZAP': 'Analyse dynamique des contrôles de sécurité HTTP.',
    'SSL Labs': 'Évaluation externe de la configuration TLS.',
    'NVD': 'Corrélation des produits versionnés avec les CVE du NIST.',
}
HEADER_SNIPPETS = {
    'content security policy': ('Content-Security-Policy', "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'self'\" always;", "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'self'\"") ,
    'strict-transport-security': ('Strict-Transport-Security', 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;', 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'),
    'x-content-type-options': ('X-Content-Type-Options', 'add_header X-Content-Type-Options "nosniff" always;', 'Header always set X-Content-Type-Options "nosniff"'),
    'x-frame-options': ('X-Frame-Options', 'add_header X-Frame-Options "SAMEORIGIN" always;', 'Header always set X-Frame-Options "SAMEORIGIN"'),
}


def _score(value):
    return normalize_score(value)


def _severity(score):
    return level_from_score(score)


def _priority(severity):
    mapping = {'Critique': 9.0, 'Élevé': 7.0, 'Moyen': 4.0, 'Faible': 0.0}
    return priority_from_score(mapping.get(severity, 0.0))['label']


def _clean_raw(value):
    return ANSI_RE.sub('', str(value or '')).replace('\r', '')


def _matching_lines(raw, patterns, limit=8):
    lines = [line.strip() for line in _clean_raw(raw).splitlines()]
    selected = [line for line in lines if any(re.search(p, line, re.I) for p in patterns)]
    if selected:
        return '\n'.join(selected[:limit])
    return '\n'.join(line for line in lines if line)[:800]


def _relevant_nvd(results):
    """Nettoie également les anciens scans déjà enrichis avec des mots génériques."""
    detected = {}
    for technology in (results.get('whatweb') or {}).get('technologies') or []:
        name, versions = _versioned_product(technology)
        if name:
            detected[name.lower()] = name
    relevant = []
    for cve in results.get('nvd_cves') or []:
        description = cve.get('description') or ''
        products = cve.get('technologies') or []
        matched_cpe = str(cve.get('matched_cpe') or cve.get('cpe') or '')
        cpe_verified = cve.get('cpe_verified') is True and matched_cpe.startswith('cpe:2.3:')
        if cpe_verified and any(product.lower() in detected and _product_in_description(product, description) for product in products):
            relevant.append(cve)
    return relevant


def _header_remediation(name):
    lower = name.lower()
    for marker, remediation in ZAP_REMEDIATION_TEMPLATES.items():
        if marker in lower:
            return remediation
    for marker, (header, nginx, apache) in HEADER_SNIPPETS.items():
        if marker in lower:
            return {
                'recommendation': f'Configurer explicitement l’en-tête HTTP {header} sur toutes les réponses.',
                'steps': [f'Nginx : {nginx}', f'Apache : {apache}', f'Vérifier avec « curl -I https://<hôte> » que {header} est présent.'],
            }
    return None


def _finding(component, evidence, kind, asset, score, remediation, identifier='', description=''):
    score = _score(score)
    severity = _severity(score)
    return {
        'source_id': identifier, 'component': component, 'evidence': evidence,
        'type': kind, 'asset': asset, 'score': score, 'severity': severity,
        'recommendation': remediation['recommendation'], 'steps': remediation['steps'],
        'priority': priority_from_score(score)['label'],
        'priority_code': priority_from_score(score)['code'], 'description': description,
    }


def _build_findings(scan, results):
    findings = []
    ssl_raw = results.get('sslscan') or results.get('nmap') or ''
    vulnerabilities = [str(item) for item in results.get('vulnerabilities') or []]
    if any(item in vulnerabilities for item in ('TLSv1.0', 'TLSv1.1')):
        findings.append(_finding('TLSv1.0 / TLSv1.1', _matching_lines(ssl_raw, [r'TLSv1\.[01].*(enabled|vulnerable|obsolete)']), 'Configuration', scan.domaine, 7.5, REMEDIATION_TEMPLATES['tls_legacy'], ''))
    weak_cipher_raw = _clean_raw(ssl_raw)
    has_3des = bool(re.search(r'(?:3DES|DES-CBC3)', weak_cipher_raw, re.I))
    has_rc4 = bool(re.search(r'\bRC4\b', weak_cipher_raw, re.I))
    if 'WEAK_CIPHER' in vulnerabilities or has_3des or has_rc4:
        observed = '/'.join(name for name, present in (('3DES', has_3des), ('RC4', has_rc4)) if present)
        component = f"Suites de chiffrement faibles ({observed})" if observed else 'Suites de chiffrement faibles'
        findings.append(_finding(
            component,
            _matching_lines(ssl_raw, [r'3DES', r'DES-CBC3', r'RC4', r'SWEET32']),
            'Configuration', scan.domaine, 7.5, REMEDIATION_TEMPLATES['weak_cipher'],
            'CVE-2016-2183' if has_3des else '',
        ))

    risk_scores = {'critical': 9.0, 'high': 7.5, 'medium': 5.0}
    for zap in results.get('zap_findings') or []:
        risk = str(zap.get('risk', '')).lower()
        if risk not in risk_scores:
            continue
        remediation = _header_remediation(zap.get('name', '')) or {
            'recommendation': 'Analyser le contrôle signalé par ZAP et corriger le composant concerné selon sa documentation de sécurité.',
            'steps': ['Identifier dans le code ou la configuration la réponse signalée par ZAP.', 'Appliquer une correction ciblée en préproduction et ajouter un test de non-régression.', 'Rejouer ZAP sur l’URL concernée et archiver la preuve de correction.'],
        }
        evidence = f"ZAP [{zap.get('risk', '?')}] {_translate_zap_label(zap.get('name', 'Alerte'))}\nURL : {zap.get('url', scan.domaine)}\nOccurrences : {zap.get('count', 1)}"
        findings.append(_finding(_translate_zap_label(zap.get('name', 'Alerte ZAP')), evidence, 'Technique', zap.get('url') or scan.domaine, risk_scores[risk], remediation, description=zap.get('description', '')))

    for nucleus in results.get('nuclei_findings') or []:
        severity = str(nucleus.get('severity', '')).lower()
        score = {'critical': 9.5, 'high': 8.0, 'medium': 5.0}.get(severity, 0)
        if score < 4:
            continue
        component = nucleus.get('name') or nucleus.get('template_id') or 'Composant obsolète'
        evidence = nucleus.get('matched_at') or nucleus.get('url') or str(nucleus)[:600]
        findings.append(_finding(component, evidence, 'Technique', nucleus.get('url') or scan.domaine, score, REMEDIATION_TEMPLATES['obsolete_software'], nucleus.get('template_id', '')))

    nmap = _clean_raw(results.get('nmap'))
    ports = sorted({int(value) for value in re.findall(r'(?m)^\s*(\d+)/tcp\s+open\b', nmap)})
    nonstandard = [port for port in ports if port not in STANDARD_PORTS]
    if nonstandard:
        remediation = dict(REMEDIATION_TEMPLATES['exposed_ports'])
        remediation['recommendation'] = f"Examiner et fermer les ports non standards suivants s’ils ne sont pas indispensables : {', '.join(map(str, nonstandard))}."
        findings.append(_finding('Ports réseau non essentiels exposés', _matching_lines(nmap, [rf'^{port}/tcp\s+open' for port in nonstandard]), 'Exposition', scan.domaine, 5.0, remediation))

    for cve in _relevant_nvd(results):
        product = ', '.join(cve.get('technologies') or []) or cve.get('cve_id', 'CVE')
        remediation = dict(REMEDIATION_TEMPLATES['obsolete_software'])
        remediation['recommendation'] = f"Mettre à jour {product} vers une version corrigée référencée par {cve.get('cve_id', 'la NVD')}."
        evidence = f"WhatWeb/NVD : {product}\n{(cve.get('description') or '')[:500]}"
        findings.append(_finding(product, evidence, 'Technique', scan.domaine, cve.get('cvss_score'), remediation, cve.get('cve_id', ''), cve.get('description', '')))

    existing_cve_ids = {item['source_id'] for item in findings if item.get('source_id')}
    for cve in collect_cves(scan, results):
        cve_id = cve['cve_id']
        if cve_id in existing_cve_ids:
            continue
        recommendation = cve.get('recommendation') or f"Appliquer la remédiation publiée pour {cve_id}, puis vérifier la version corrigée."
        remediation = {
            'recommendation': recommendation,
            'steps': [
                f"Identifier le composant concerné par {cve_id}.",
                "Appliquer la mise à jour ou la correction de configuration recommandée.",
                "Relancer le scan et archiver la preuve de correction.",
            ],
        }
        product = cve.get('produit_concerne') or cve_id
        evidence_parts = [cve.get('description') or cve_id]
        if cve.get('lien_nvd'):
            evidence_parts.append(cve['lien_nvd'])
        findings.append(_finding(
            product, '\n'.join(evidence_parts)[:900], 'CVE', scan.domaine,
            cve.get('cvss_score'), remediation, cve_id, cve.get('description', ''),
        ))
        existing_cve_ids.add(cve_id)

    unique = {}
    for item in findings:
        key = (item['source_id'], item['component'], item['asset'])
        if key not in unique or item['score'] > unique[key]['score']:
            unique[key] = item
    ordered = recommendation_order(list(unique.values()))
    for index, item in enumerate(ordered, 1):
        item['id'] = item.get('source_id') or f'VULN-{index:03d}'
    return ordered


def _table(rows, widths, styles, repeat_rows=1):
    table = Table(rows, colWidths=widths, repeatRows=repeat_rows)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dbeafe')),
        ('TEXTCOLOR', (0, 0), (-1, 0), COLOR_PRIMARY),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_BG]),
        ('BOX', (0, 0), (-1, -1), .6, COLOR_MUTED),
        ('INNERGRID', (0, 0), (-1, -1), .3, colors.HexColor('#bfdbfe')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5), ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    return table


def _cell(value, styles, bold=False):
    text = _escape(value).replace('\n', '<br/>')
    return Paragraph(f'<b>{text}</b>' if bold else text, styles['CSTableCell'])

def _table_recommendation(text, styles):
    recommendation_style = styles['CSBody'].clone('CSTableRecommendation', spaceBefore=8)
    return Paragraph(f'<b>Recommandation :</b> {_escape(text)}', recommendation_style)


def _link_cell(url, styles, label='Fiche NVD'):
    safe_url = _escape(url)
    safe_label = _escape(label)
    return Paragraph(f'<link href="{safe_url}" color="#0ea5e9">{safe_label}</link>', styles['CSTableCell'])


def _activated_tools(results):
    return tool_names_with_results(results)


def _technology_rows(results, styles):
    rows = [[_cell('Technologie', styles, True), _cell('Version', styles, True), _cell('Détails observés', styles, True)]]
    for technology in (results.get('whatweb') or {}).get('technologies') or []:
        versions = technology.get('version') or []
        strings = technology.get('string') or []
        rows.append([
            _cell(technology.get('name') or '—', styles),
            _cell(', '.join(map(str, versions)) or '—', styles),
            _cell(', '.join(map(str, strings)) or '—', styles),
        ])
    if len(rows) == 1:
        rows.append([_cell('—', styles), _cell('—', styles), _cell('Aucune technologie extraite par WhatWeb.', styles)])
    return rows


def _port_rows(results, styles):
    rows = [[_cell('Port', styles, True), _cell('État', styles, True), _cell('Service', styles, True), _cell('Détails Nmap', styles, True)]]
    for item in extract_ports(results):
        rows.append([
            _cell(f"{item['port']}/{item['protocol']}", styles), _cell(item['state'], styles),
            _cell(item['service'], styles), _cell(item.get('details') or '—', styles),
        ])
    if len(rows) == 1:
        rows.append([_cell('—', styles), _cell('Aucun port ouvert extrait', styles), _cell('—', styles), _cell('—', styles)])
    return rows


FRENCH_MONTHS = (
    '', 'janvier', 'février', 'mars', 'avril', 'mai', 'juin',
    'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre',
)


def _french_decimal(value):
    return f'{float(value):.1f}'.replace('.', ',')


def _summary_table_rows(metrics, certificate):
    severity = metrics['severity']

    def label(count, singular, plural):
        return singular if count in (0, 1) else plural

    if not certificate:
        certificate_count = 0
        certificate_label = 'Certificat SSL détecté'
    elif certificate.get('expired') is True:
        certificate_count = 1
        certificate_label = 'Certificat SSL expiré'
    elif certificate.get('expired') is False:
        certificate_count = 1
        certificate_label = 'Certificat SSL valide'
    else:
        certificate_count = 1
        certificate_label = 'Certificat SSL présent'

    return [
        (label(severity['Élevé'], 'Vulnérabilité élevée', 'Vulnérabilités élevées'), severity['Élevé']),
        (label(severity['Critique'], 'Vulnérabilité critique', 'Vulnérabilités critiques'), severity['Critique']),
        (label(metrics['cves'], 'CVE officielle', 'CVE officielles'), metrics['cves']),
        (label(metrics['port_count'], 'Port ouvert', 'Ports ouverts'), metrics['port_count']),
        (label(metrics['service_count'], 'Service détecté', 'Services détectés'), metrics['service_count']),
        (label(metrics['technology_count'], 'Technologie', 'Technologies'), metrics['technology_count']),
        (label(metrics['tls_count'], 'Version TLS', 'Versions TLS'), metrics['tls_count']),
        (label(metrics['cipher_count'], 'Suite cryptographique', 'Suites cryptographiques'), metrics['cipher_count']),
        (certificate_label, certificate_count),
    ]

def _summary_paragraphs(scan, risk_label, risk_score, security_score, metrics):
    if scan.date_scan:
        scan_date = (
            f'{scan.date_scan.day} {FRENCH_MONTHS[scan.date_scan.month]} '
            f'{scan.date_scan.year} à {scan.date_scan:%H:%M}'
        )
    else:
        scan_date = 'date non renseignée'

    intro = (
        'Le rapport présente un audit de sécurité du domaine '
        f'<b>{_escape(scan.domaine)}</b>, réalisé le <b>{_escape(scan_date)}</b>, '
        f"sous l'identifiant de scan <b>{scan.id}</b>. Le document classe le niveau de risque "
        f'comme <b>{_escape(risk_label)}</b>, avec un <b>score IA de '
        f'{_french_decimal(risk_score)}/10</b> et un <b>score de sécurité de '
        f'{_french_decimal(security_score)}/10</b>.'
    )

    ports = metrics.get('ports') or []
    if len(ports) == 1:
        port = ports[0]
        port_number = int(port['port'])
        service = str(port.get('service') or 'non identifié').strip().upper()
        port_text = (
            f'Le seul port ouvert détecté est le <b>port {port_number}</b>, utilisé pour le '
            f'service <b>{_escape(service)}</b>.'
        )
        if port_number == 443 and service == 'HTTPS':
            port_text += ' Cette ouverture est normale pour un site web sécurisé.'
        else:
            port_text += ' Cette exposition doit être vérifiée et justifiée selon le besoin du service.'
    elif ports:
        exposed = ', '.join(
            f"{int(item['port'])} ({str(item.get('service') or 'non identifié').upper()})"
            for item in ports
        )
        port_text = f'Les ports ouverts détectés sont : <b>{_escape(exposed)}</b>.'
    else:
        port_text = 'Aucun port ouvert n’a été détecté dans les résultats disponibles.'

    return intro, port_text

def _cached_report(scan):
    media_root = Path(getattr(settings, 'MEDIA_ROOT', settings.BASE_DIR / 'media'))
    for report in scan.rapports.order_by('-date_generation'):
        raw = Path(report.chemin_pdf)
        candidate = raw if raw.is_absolute() else media_root / raw
        if candidate.is_file():
            return report
    return None


def generate_fixed_pdf_for_scan(scan, force_regenerate=False):
    if not force_regenerate:
        cached = _cached_report(scan)
        if cached:
            return cached

    styles = _build_styles()
    results = normalize_results(scan.resultats_ssl or {})
    findings = _build_findings(scan, results)
    analysis = build_report_analysis(scan, results, findings)
    metrics = analysis['metrics']
    risk_score = analysis['score']
    risk_label, risk_color = risk_level_from_score(risk_score)
    security_score = _score(security_score_from_risk(risk_score))
    active_tools = analysis['metrics']['tools']

    safe_domain = re.sub(r'[^\w.\-]+', '_', scan.domaine)[:80]
    path = _reports_dir() / f"rapport_cyberscan_{scan.id}_{safe_domain}_{datetime.utcnow():%Y%m%d_%H%M%S}.pdf"
    doc = CyberScanDocTemplate(
        str(path), pagesize=A4, leftMargin=15*mm, rightMargin=15*mm,
        topMargin=18*mm, bottomMargin=22*mm,
        title='Rapport de sécurité CyberScan', author='CyberScan',
    )
    doc.history_url = _history_url()
    logo = _logo_path()
    logo_cell = (
        Image(logo, width=5.2*cm, height=1.3*cm)
        if logo else Paragraph('CYBERSCAN', styles['CSHeading'])
    )
    title_style = styles['CSTitle'].clone(
        'CSCoverInlineTitle', fontSize=16, leading=19, spaceAfter=0, alignment=TA_CENTER,
    )
    cover_header = Table([[
        logo_cell,
        Paragraph('Rapport de sécurité CyberScan', title_style),
        _history_qr_block(doc.history_url),
    ]], colWidths=[5.5*cm, 9.3*cm, 3.2*cm])
    cover_header.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
        ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    story = [Spacer(1, .15*cm), cover_header, Spacer(1, 1.7*cm)]
    raw_domain = str(scan.domaine or '').strip()
    target_url = raw_domain if re.match(r'^https?://', raw_domain, re.IGNORECASE) else f'https://{raw_domain}'
    cover_rows = [
        ('Date et heure du scan', scan.date_scan.strftime('%d/%m/%Y à %H:%M') if scan.date_scan else '—'),
        ('Identifiant unique du scan', str(scan.id)),
        ('Client', getattr(scan.client, 'nom', None) or 'Non renseigné'),
    ]
    cover_table_rows = [
        [_cell('Information', styles, True), _cell('Valeur', styles, True)],
        [_cell('URL', styles, True), _link_cell(target_url, styles, target_url)],
        *[[_cell(label, styles, True), _cell(value, styles)] for label, value in cover_rows],
    ]
    story.extend([
        _section_title(styles, 'Informations générales'),
        _table(cover_table_rows, [5.3*cm, 8.7*cm], styles),
        Spacer(1, 1*cm),
    ])
    banner = Table([[_cell(
        f'NIVEAU DE RISQUE : {risk_label.upper()}\nScore IA : {risk_score:.1f}/10 — Score sécurité : {security_score:.1f}/10',
        styles, True,
    )]], colWidths=[14*cm])
    banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color), ('TEXTCOLOR', (0, 0), (-1, -1), COLOR_WHITE),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.extend([banner, Spacer(1, 6), Paragraph('Document confidentiel — Usage interne uniquement', styles['CSSmall']), PageBreak()])

    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle('TOCLevel0', parent=styles['CSBody'], fontSize=10, leading=15, leftIndent=8, textColor=COLOR_PRIMARY)]
    story.extend([Paragraph('Sommaire', styles['CSTitle']), Spacer(1, 8), toc, PageBreak()])

    summary_intro, summary_port = _summary_paragraphs(
        scan, risk_label, risk_score, security_score, metrics,
    )
    story.extend([
        _toc_heading('1. Synthèse analytique', styles),
        Paragraph(summary_intro, styles['CSBody']),
    ])
    summary_rows = _summary_table_rows(metrics, results.get('certificate') or {})
    summary_recommendation = (
        findings[0]['recommendation']
        if findings else 'Maintenir les contrôles actuels et programmer un nouveau scan périodique.'
    )
    story.append(_table([[_cell('Mesure', styles, True), _cell('Valeur réelle', styles, True)]] +
                        [[_cell(label, styles), _cell(value, styles)] for label, value in summary_rows],
                        [8.2*cm, 8.5*cm], styles))
    story.append(_table_recommendation(summary_recommendation, styles))
    story.append(Paragraph(summary_port, styles['CSBody']))

    story.append(_toc_heading('2. Méthodologie', styles))
    for tool in active_tools:
        story.append(Paragraph(f'<b>{_escape(tool)}</b> — {_escape(TOOL_DESCRIPTIONS.get(tool, "Résultat technique enregistré"))}', styles['CSBullet']))

    story.extend([
        _toc_heading('3. Inventaire technique', styles),
        Paragraph('Technologies détectées', styles['CSHeading']),
        _table(_technology_rows(results, styles), [4.2*cm, 3.3*cm, 9.2*cm], styles),
        _table_recommendation('Maintenir un inventaire à jour et corriger ou mettre à niveau toute technologie obsolète ou non nécessaire.', styles),
        Paragraph('Ports exposés', styles['CSHeading']),
        _table(_port_rows(results, styles), [2.8*cm, 2.6*cm, 4.6*cm, 6.7*cm], styles),
        _table_recommendation('Limiter les ports ouverts aux seuls services indispensables et contrôler régulièrement leur exposition.', styles),
    ])

    story.append(_toc_heading('4. Indicateurs et analyse IA', styles))
    from .report_graphics import graphical_indicators
    story.extend(graphical_indicators(scan, results, findings, active_tools, styles))

    story.append(_toc_heading('5. Fiches vulnérabilité', styles))
    for finding in findings:
        story.append(Paragraph(_escape(finding['id']), styles['CSHeading']))
        fields = [
            ('Identifiant', finding['id']), ('Composant', finding['component']),
            ('Preuve', finding['evidence']), ('Score CVSS', f"{finding['score']:.1f}"),
            ('Criticité', finding['severity']), ('Recommandation', finding['recommendation']),
            ('Priorité', f"{finding['priority_code']} — {finding['priority']}"),
        ]
        story.append(_table([[_cell('Champ obligatoire', styles, True), _cell('Valeur issue du constat', styles, True)]] +
                            [[_cell(label, styles, True), _cell(value, styles)] for label, value in fields],
                            [5.2*cm, 11.5*cm], styles))
        story.append(_table_recommendation(finding['recommendation'], styles))

    story.append(_section_title(styles, 'Plan de correction'))
    plan_rows = [[_cell('Priorité', styles, True), _cell('Identifiant / composant', styles, True), _cell('Action corrective', styles, True)]]
    for action in analysis['plan']:
        plan_rows.append([
            _cell(f"{action['priority_code']} — {action['priority']}", styles),
            _cell(f"{action['id']} — {action['component']}", styles),
            _cell(action['recommendation'], styles),
        ])
    if not analysis['plan']:
        plan_rows.append([_cell('—', styles), _cell('Aucun constat', styles), _cell('Aucune action corrective déduite des résultats.', styles)])
    story.append(_table(plan_rows, [3.2*cm, 5.2*cm, 8.3*cm], styles))
    story.append(_table_recommendation(
        'Appliquer d’abord les actions P1, documenter les corrections réalisées, puis relancer un scan de validation.',
        styles,
    ))

    story.append(_section_title(styles, 'Annexe CVE'))
    cve_rows = [[
        _cell('CVE ID', styles, True), _cell('CVSS', styles, True),
        _cell('Produit concerné', styles, True), _cell('Description enregistrée', styles, True),
        _cell('Lien NVD', styles, True),
    ]]
    for cve in metrics['cve_records']:
        cve_rows.append([
            _cell(cve['cve_id'], styles),
            _cell(f"{float(cve.get('cvss_score') or 0):.1f}", styles),
            _cell(cve.get('produit_concerne') or 'Produit non transmis par la source CVE', styles),
            _cell(cve.get('description') or 'Description non transmise par la source CVE', styles),
            _link_cell(cve['lien_nvd'], styles),
        ])
    if not metrics['cve_records']:
        cve_rows.append([
            _cell('—', styles), _cell('—', styles), _cell('—', styles),
            _cell('Aucune CVE enregistrée dans ce scan.', styles), _cell('—', styles),
        ])
    story.append(_table(cve_rows, [2.6*cm, 1.4*cm, 3.2*cm, 6.3*cm, 3.2*cm], styles))
    cve_recommendation = (
        'Appliquer les correctifs officiels des CVE recensées et confirmer les versions corrigées lors du prochain scan.'
        if metrics['cve_records']
        else 'Maintenir une veille NVD régulière afin de détecter rapidement toute nouvelle CVE applicable.'
    )
    story.append(_table_recommendation(cve_recommendation, styles))

    story.extend([
        PageBreak(), _toc_heading('6. Conclusion', styles),
        Paragraph(_escape(analysis['conclusion']), styles['CSBody']), CertificationStamp(scan.id),
    ])
    doc.build_with_toc(story)

    media_root = Path(getattr(settings, 'MEDIA_ROOT', settings.BASE_DIR / 'media')).resolve()
    try:
        relative_path = str(path.resolve().relative_to(media_root)).replace('\\', '/')
    except ValueError:
        relative_path = str(path)
    report = Rapport.objects.create(scan=scan, chemin_pdf=relative_path)
    from .realtime_service import publish_event
    publish_event('report.created', scan, {'report_id': report.id, 'format': 'PDF'})
    try:
        from .notification_service import notify_report_ready
        notify_report_ready(scan, 'PDF')
    except Exception:
        logger.warning('Notification PDF échouée pour le scan %s', scan.id, exc_info=True)
    return report
