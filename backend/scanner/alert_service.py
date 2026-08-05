from __future__ import annotations

from .ai_module.chatbot import format_score
from .cve_data import collect_scan_cves


SOURCE_LABELS = {
    'ssl': 'SSLScan',
    'cve': 'Base NVD / CVE',
    'manual': 'Vulnérabilité manuelle',
    'nuclei': 'Nuclei',
    'zap': 'OWASP ZAP',
    'scan': 'Analyse globale du scan',
}


def severity_from_score(score):
    value = float(score or 0)
    if value >= 7:
        return 'CRITIQUE'
    if value >= 4:
        return 'MOYEN'
    return 'FAIBLE'


def frontend_type(severity):
    return {'CRITIQUE': 'danger', 'MOYEN': 'warn', 'FAIBLE': 'ok'}[severity]


def _display_value(value):
    if value in (None, '', [], {}):
        return ''
    if isinstance(value, (list, tuple, set)):
        return ', '.join(str(item).strip() for item in value if str(item).strip())
    return str(value).strip()


def _field(label, value, url=''):
    display_value = _display_value(value)
    if not display_value:
        return None
    field = {'label': label, 'value': display_value}
    safe_url = str(url or '').strip()
    if safe_url.startswith(('https://', 'http://')):
        field['url'] = safe_url
    return field


def _details(source, source_id='', fields=None, recommendation=''):
    return {
        'source_label': SOURCE_LABELS[source],
        'identifier': _display_value(source_id),
        'fields': [field for field in (fields or []) if field],
        'recommendation': _display_value(recommendation),
    }


def _alert(scan, title, message, severity, source, source_id='', details=None):
    return {
        'scan_id': scan.id,
        'domain': scan.domaine,
        'icon': '⚠' if severity == 'CRITIQUE' else '!' if severity == 'MOYEN' else 'i',
        'titre': title,
        'message': message,
        'date': scan.date_scan.isoformat() if scan.date_scan else None,
        'niveau': severity,
        'type': frontend_type(severity),
        'source': source,
        'source_id': source_id,
        'details': details or _details(source, source_id),
    }


def build_alerts(scans):
    alerts = []
    for scan in scans:
        results = scan.resultats_ssl if isinstance(scan.resultats_ssl, dict) else {}
        for vulnerability in dict.fromkeys(results.get('vulnerabilities') or []):
            definitions = {
                'TLSv1.0': (
                    'CRITIQUE',
                    'Protocole obsolète signalé par SSLScan et à désactiver au profit de TLS 1.2 ou 1.3.',
                    'Désactiver TLS 1.0 sur le serveur et n’autoriser que TLS 1.2 ou TLS 1.3.',
                ),
                'TLSv1.1': (
                    'MOYEN',
                    'Protocole déprécié à désactiver au profit de TLS 1.2 ou 1.3.',
                    'Désactiver TLS 1.1 et vérifier la compatibilité des clients avec TLS 1.2 ou TLS 1.3.',
                ),
                'WEAK_CIPHER': (
                    'CRITIQUE',
                    'Suite de chiffrement faible 3DES ou RC4 signalée par SSLScan.',
                    'Retirer les suites 3DES et RC4, puis privilégier AES-GCM ou ChaCha20-Poly1305.',
                ),
            }
            if vulnerability in definitions:
                severity, message, recommendation = definitions[vulnerability]
                alerts.append(_alert(
                    scan,
                    f'{vulnerability} détecté — {scan.domaine}',
                    message,
                    severity,
                    'ssl',
                    vulnerability,
                    _details(
                        'ssl',
                        vulnerability,
                        fields=[
                            _field('Élément concerné', 'Configuration des protocoles TLS'),
                            _field('Domaine analysé', scan.domaine),
                        ],
                        recommendation=recommendation,
                    ),
                ))
        for cve in collect_scan_cves(scan, results):
            severity = severity_from_score(cve['cvss_score'])
            alerts.append(_alert(
                scan,
                f"{cve['cve_id']} — {scan.domaine}",
                f"{cve['description']} (CVSS {format_score(cve['cvss_score'])}/10)",
                severity,
                'cve',
                cve['cve_id'],
                _details(
                    'cve',
                    cve['cve_id'],
                    fields=[
                        _field('Score CVSS', f"{format_score(cve['cvss_score'])}/10"),
                        _field('Produit concerné', cve.get('produit_concerne')),
                        _field('Date de publication', cve.get('published_date')),
                        _field('Fiche NVD', cve.get('lien_nvd'), cve.get('lien_nvd')),
                    ],
                    recommendation=cve.get('recommendation') or cve.get('recommandation_ia'),
                ),
            ))
        for vulnerability in scan.vulnerabilites_manuelles.all():
            severity = {'critical': 'CRITIQUE', 'high': 'CRITIQUE', 'medium': 'MOYEN', 'low': 'FAIBLE'}.get(
                (vulnerability.risk or '').lower(), severity_from_score(vulnerability.cvss_score)
            )
            alerts.append(_alert(
                scan,
                f'{vulnerability.nom} — {scan.domaine}',
                vulnerability.description,
                severity,
                'manual',
                str(vulnerability.id),
                _details(
                    'manual',
                    str(vulnerability.id),
                    fields=[
                        _field('Type', vulnerability.get_type_vuln_display()),
                        _field('Élément impacté', vulnerability.impacted_element),
                        _field('Score CVSS', f'{format_score(vulnerability.cvss_score)}/10'),
                        _field('Vecteur CVSS', vulnerability.cvss_vector),
                        _field('Priorité', vulnerability.priorite),
                        _field('Complexité', vulnerability.complexite),
                        _field('Risques techniques et métier', vulnerability.technical_business_risks),
                        _field('Preuve de concept', vulnerability.proof_of_concept),
                        _field('Références', vulnerability.references),
                    ],
                    recommendation=vulnerability.recommandation,
                ),
            ))
        for finding in results.get('nuclei_findings') or []:
            raw = str(finding.get('severity') or 'info').lower()
            severity = {'critical': 'CRITIQUE', 'high': 'CRITIQUE', 'medium': 'MOYEN'}.get(raw, 'FAIBLE')
            name = finding.get('name') or finding.get('template_id') or 'Vulnérabilité Nuclei'
            source_id = str(finding.get('template_id') or '')
            alerts.append(_alert(
                scan,
                f'{name} — {scan.domaine}',
                finding.get('description') or '',
                severity,
                'nuclei',
                source_id,
                _details(
                    'nuclei',
                    source_id,
                    fields=[
                        _field('Sévérité Nuclei', raw.upper()),
                        _field(
                            'URL ou hôte concerné',
                            finding.get('matched_at') or finding.get('matched-at') or finding.get('host'),
                        ),
                        _field('Matcher', finding.get('matcher_name') or finding.get('matcher-name')),
                        _field('Résultats extraits', finding.get('extracted_results')),
                        _field('Références', finding.get('reference')),
                    ],
                    recommendation=finding.get('remediation') or finding.get('solution'),
                ),
            ))
        for finding in results.get('zap_findings') or []:
            raw = str(finding.get('risk') or 'low').split()[0].lower()
            severity = {'critical': 'CRITIQUE', 'high': 'CRITIQUE', 'medium': 'MOYEN'}.get(raw, 'FAIBLE')
            name = finding.get('name') or 'Vulnérabilité ZAP'
            source_id = str(finding.get('pluginid') or '')
            alerts.append(_alert(
                scan,
                f'{name} — {scan.domaine}',
                (finding.get('description') or '')[:300],
                severity,
                'zap',
                source_id,
                _details(
                    'zap',
                    source_id,
                    fields=[
                        _field('Niveau de risque ZAP', finding.get('risk')),
                        _field('URL concernée', finding.get('url'), finding.get('url')),
                        _field('Paramètre', finding.get('param') or finding.get('parameter')),
                        _field('Preuve observée', finding.get('evidence')),
                        _field('Nombre d’occurrences', finding.get('count')),
                        _field('Confiance', finding.get('confidence')),
                        _field('Références', finding.get('reference')),
                    ],
                    recommendation=finding.get('solution'),
                ),
            ))
        if not any(item['scan_id'] == scan.id for item in alerts):
            alerts.append(_alert(
                scan,
                f'Scan terminé — {scan.domaine}',
                f'Aucune vulnérabilité enregistrée. Score IA: {format_score(scan.score_risque_ia)}/10.',
                'FAIBLE',
                'scan',
                str(scan.id),
                _details(
                    'scan',
                    str(scan.id),
                    fields=[
                        _field('Domaine analysé', scan.domaine),
                        _field('Score de risque IA', f'{format_score(scan.score_risque_ia)}/10'),
                    ],
                    recommendation='Continuer la surveillance et planifier des scans réguliers.',
                ),
            ))
    return alerts


def alert_stats(alerts):
    return {
        'critiques': sum(item['niveau'] == 'CRITIQUE' for item in alerts),
        'moyennes': sum(item['niveau'] == 'MOYEN' for item in alerts),
        'faibles': sum(item['niveau'] == 'FAIBLE' for item in alerts),
        'total': len(alerts),
    }
