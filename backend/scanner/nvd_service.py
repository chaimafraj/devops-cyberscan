"""Service d'enrichissement CVE via l'API NVD (NIST) v2.0.

Après chaque scan, ce service utilise les technologies détectées par WhatWeb
(et, en complément, les versions de produits repérées dans la sortie brute de
Nmap / OpenSSL) pour rechercher automatiquement les CVE correspondantes sur
l'API publique du NVD.

Chaque CVE renvoyée contient exactement les champs demandés :
    - cve_id
    - cvss_score
    - severity
    - description
    - published_date

Le résultat est destiné à être sauvegardé dans ``resultats_ssl["nvd_cves"]``.

Ce module ne modifie pas les scanners existants : il se contente de consommer
leurs sorties (technologies WhatWeb, brut Nmap/OpenSSL).

Docs API : https://nvd.nist.gov/developers/vulnerabilities
"""

import os
import re

import requests

from .cve_data import nvd_url_for


NVD_CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_RESULTS_PER_TECHNOLOGY = 10
# Sans clé API, le NVD tolère 5 requêtes par fenêtre glissante de 30 s. On borne
# le nombre de requêtes par scan pour éviter un 429. Configurer NVD_API_KEY pour
# des scans plus larges.
NVD_PUBLIC_REQUEST_LIMIT = 5

_GENERIC_WHATWEB_NAMES = {
    'country', 'title', 'ip', 'cookies', 'cookie', 'html5', 'httpserver',
    'uncommonheaders', 'x-frame-options', 'x-xss-protection', 'httponly',
    'script', 'redirectlocation', 'email', 'meta-generator',
}
_VERSION_RE = re.compile(r'\d+(?:\.\d+)+(?:[a-z0-9._-]*)?', re.IGNORECASE)

# Correspondances CPE relues manuellement. Toute technologie absente est ignorée
# plutôt que de recevoir une CVE approximative issue d’une recherche textuelle.
_VALIDATED_CPE_PRODUCTS = {
    'nginx': ('f5', 'nginx'),
    'apache': ('apache', 'http_server'),
    'apache http server': ('apache', 'http_server'),
    'openssh': ('openbsd', 'openssh'),
    'openssl': ('openssl', 'openssl'),
    'wordpress': ('wordpress', 'wordpress'),
}


def _validated_cpe(name, version):
    mapping = _VALIDATED_CPE_PRODUCTS.get(str(name).strip().lower())
    if not mapping:
        return ''
    vendor, product = mapping
    safe_version = str(version).strip().replace(' ', r'\ ')
    return f'cpe:2.3:a:{vendor}:{product}:{safe_version}:*:*:*:*:*:*:*'

def _versioned_product(technology):
    """Retourne (produit, versions) uniquement pour une technologie exploitable."""
    name = str(technology.get('name', '')).strip()
    if not name or name.lower() in _GENERIC_WHATWEB_NAMES:
        return None, []
    versions = technology.get('version') or []
    if not isinstance(versions, list):
        versions = [versions]
    versions = [str(value).strip() for value in versions if _VERSION_RE.search(str(value))]
    return (name, versions) if versions else (None, [])


def _product_in_description(product, description):
    """Évite les correspondances NVD dues à un mot générique ou un paramètre."""
    return bool(re.search(rf'(?<![\w-]){re.escape(product)}(?![\w-])', description or '', re.IGNORECASE))
# Produits fréquemment exposés dans les sorties Nmap (ssl-enum-ciphers) et
# OpenSSL (s_client). On extrait "produit + version" pour interroger le NVD.
_VERSION_PATTERNS = [
    re.compile(r'\b(OpenSSL)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z]?)', re.IGNORECASE),
    re.compile(r'\b(nginx)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.IGNORECASE),
    re.compile(r'\b(Apache)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.IGNORECASE),
]


def _description(cve):
    """Retourne la description anglaise du CVE (ou la première disponible)."""
    descriptions = cve.get('descriptions', [])
    english = next((item.get('value', '') for item in descriptions if item.get('lang') == 'en'), '')
    return english or (descriptions[0].get('value', '') if descriptions else '')


def _severity_from_score(score):
    """Déduit une sévérité qualitative depuis un score CVSS (barème NVD v3)."""
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    if score > 0.0:
        return 'LOW'
    return 'UNKNOWN'


def _cvss_score_and_severity(cve):
    """Extrait (score, severity) en privilégiant CVSS v3.1 puis v3.0 puis v2."""
    metrics = cve.get('metrics', {})
    for metric_name in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        entries = metrics.get(metric_name, [])
        if not entries:
            continue
        entry = entries[0]
        cvss_data = entry.get('cvssData', {})
        score = float(cvss_data.get('baseScore', 0.0) or 0.0)
        # v3.x expose baseSeverity dans cvssData ; v2 l'expose au niveau de l'entrée.
        severity = cvss_data.get('baseSeverity') or entry.get('baseSeverity')
        return score, (severity or _severity_from_score(score)).upper()
    return 0.0, 'UNKNOWN'


def extract_products_from_raw(*raw_outputs):
    """Repère des couples produit/version dans des sorties brutes Nmap/OpenSSL.

    Retourne une liste de technologies au même format que WhatWeb
    (``{'name': ..., 'version': [...]}``) afin d'être interrogeables par le NVD.
    """
    products = {}
    for raw in raw_outputs:
        if not raw:
            continue
        for pattern in _VERSION_PATTERNS:
            for name, version in pattern.findall(raw):
                key = name.lower()
                entry = products.setdefault(key, {'name': name, 'version': []})
                if version and version not in entry['version']:
                    entry['version'].append(version)
    return list(products.values())


def _query_nvd(query, headers):
    """Interroge le NVD par mot-clé. Lève requests.RequestException / ValueError."""
    response = requests.get(
        NVD_CVE_API_URL,
        params={
            'keywordSearch': query,
            'resultsPerPage': NVD_RESULTS_PER_TECHNOLOGY,
        },
        headers=headers,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()



def _query_nvd_cpe(cpe_name, headers):
    """Interroge NVD avec un CPE 2.3 précis et validé."""
    response = requests.get(
        NVD_CVE_API_URL,
        params={'cpeName': cpe_name, 'resultsPerPage': NVD_RESULTS_PER_TECHNOLOGY},
        headers=headers,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()

def find_cves_for_technologies(technologies):
    """Recherche les CVE NVD pour une liste de technologies (nom + versions).

    Les noms WhatWeb ne sont pas garantis d'être des identifiants CPE : on
    utilise donc l'endpoint de recherche par mot-clé. Les CVE renvoyées sont des
    candidates et conservent le nom de la technologie détectée pour la traçabilité.

    Retour : ``{'success': bool, 'cves': [...], 'errors': [...]}`` où chaque CVE
    contient cve_id, cvss_score, severity, description, published_date, technologies.
    """
    cves = {}
    errors = []
    headers = {}
    api_key = os.getenv('NVD_API_KEY')
    if api_key:
        headers['apiKey'] = api_key
    request_count = 0
    limit_reached = False

    for technology in technologies:
        if limit_reached:
            break
        name, versions = _versioned_product(technology)
        if not name:
            continue

        for version in versions:
            if not api_key and request_count >= NVD_PUBLIC_REQUEST_LIMIT:
                errors.append(
                    'Limite NVD publique atteinte; configurez NVD_API_KEY pour '
                    'rechercher les autres technologies.'
                )
                limit_reached = True
                break

            query = ' '.join(part for part in (name, str(version).strip()) if part)
            matched_cpe = _validated_cpe(name, version)
            if not matched_cpe:
                continue
            try:
                request_count += 1
                payload = _query_nvd_cpe(matched_cpe, headers)
            except (requests.RequestException, ValueError) as exc:
                errors.append(f'{query}: {str(exc) or exc.__class__.__name__}')
                continue

            for vulnerability in payload.get('vulnerabilities', []):
                cve = vulnerability.get('cve', {})
                cve_id = cve.get('id')
                if not cve_id:
                    continue
                description = _description(cve)
                if not _product_in_description(name, description):
                    continue
                score, severity = _cvss_score_and_severity(cve)
                result = cves.setdefault(cve_id, {
                    'cve_id': cve_id,
                    'cvss_score': score,
                    'severity': severity,
                    'description': description,
                    'published_date': cve.get('published', ''),
                    'technologies': [],
                    'products': [],
                    'produit_concerne': '',
                    'lien_nvd': nvd_url_for(cve_id),
                    'matched_cpe': matched_cpe,
                    'cpe_verified': True,
                })
                if name not in result['technologies']:
                    result['technologies'].append(name)
                product = f'{name} {version}'.strip()
                if product not in result['products']:
                    result['products'].append(product)
                result['produit_concerne'] = ', '.join(result['products'])

    return {
        'success': not errors,
        'cves': list(cves.values()),
        'errors': errors,
    }


def enrich_scan_with_nvd(whatweb_result=None, nmap_raw='', openssl_raw=''):
    """Point d'entrée appelé automatiquement après un scan.

    Combine les technologies WhatWeb et les versions extraites des sorties brutes
    Nmap / OpenSSL, puis interroge le NVD.

    Retour : ``{'success', 'cves', 'errors'}`` — ``cves`` est prêt à être stocké
    dans ``resultats_ssl["nvd_cves"]``.
    """
    technologies = []
    if whatweb_result and whatweb_result.get('success'):
        technologies.extend(whatweb_result.get('technologies', []) or [])

    # Complément : versions produits repérées par Nmap / OpenSSL.
    technologies.extend(extract_products_from_raw(nmap_raw, openssl_raw))

    if not technologies:
        return {'success': True, 'cves': [], 'errors': []}

    return find_cves_for_technologies(technologies)
