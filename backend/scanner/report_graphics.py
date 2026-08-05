"""Visualisations professionnelles de la section Indicateurs graphiques CyberScan."""
from __future__ import annotations

import re
from collections import Counter

from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Paragraph, Spacer, Table, TableStyle

from .report_analysis import build_report_analysis
from .report_data import (
    build_report_metrics, collect_cves, extract_cipher_suites, extract_duration_seconds, extract_ports,
)
from .report_generator import (
    COLOR_LIGHT_BG, COLOR_MUTED, COLOR_PRIMARY, COLOR_WHITE,
    _escape, risk_level_from_score,
)

BLUE = colors.HexColor('#0ea5e9')
NAVY = colors.HexColor('#0f172a')
GREEN = colors.HexColor('#16a34a')
YELLOW = colors.HexColor('#f59e0b')
ORANGE = colors.HexColor('#ea580c')
RED = colors.HexColor('#dc2626')
BORDER = colors.HexColor('#cbd5e1')
SEVERITY_COLORS = {'Critique': RED, 'Élevé': ORANGE, 'Moyen': YELLOW, 'Faible': GREEN}


def _cell(value, styles, bold=False):
    text = _escape('—' if value is None or value == '' else value).replace('\n', '<br/>')
    return Paragraph(f'<b>{text}</b>' if bold else text, styles['CSTableCell'])

def _table_recommendation(text, styles):
    recommendation_style = styles['CSBody'].clone('CSTableRecommendation', spaceBefore=8)
    return Paragraph(f'<b>Recommandation :</b> {_escape(text)}', recommendation_style)


def _table(rows, widths, repeat_rows=1):
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


def _open_ports(results):
    return extract_ports(results)

def _duration(scan, results=None):
    return extract_duration_seconds(scan, results or {})

def _format_duration(seconds):
    if seconds is None:
        return 'Non mesuré (scan historique)'
    seconds = int(round(float(seconds)))
    minutes, seconds = divmod(seconds, 60)
    return f'{minutes} min {seconds:02d} s' if minutes else f'{seconds} s'


def _severity_counts(findings):
    return {name: sum(item.get('severity') == name for item in findings)
            for name in ('Critique', 'Élevé', 'Moyen', 'Faible')}


def _cve_count(scan, results):
    return len(collect_cves(scan, results))

def _card(label, value, color, icon, styles):
    card = Table([
        [_cell(icon, styles, True)], [_cell(value, styles, True)], [_cell(label, styles)],
    ], colWidths=[3.22 * cm], rowHeights=[.55 * cm, .72 * cm, .62 * cm])
    card.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_WHITE), ('BOX', (0, 0), (-1, -1), .7, BORDER),
        ('LINEABOVE', (0, 0), (-1, 0), 3, color), ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR', (0, 0), (0, 0), color),
        ('TOPPADDING', (0, 0), (-1, -1), 2), ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    return card


def _kpis(scan, results, findings, tools, styles, metrics):
    counts, ports = metrics['severity'], metrics['ports']
    risk = float(scan.score_risque_ia or 0)
    level, _ = risk_level_from_score(risk)
    technologies = metrics['technologies']
    values = [
        ('Score IA', f'{risk:.1f}/10', BLUE, 'IA'), ('Score sécurité dérivé', f'{round((10-risk)*10)}/100', colors.HexColor('#2563eb'), 'S'),
        ('Niveau de risque', level, SEVERITY_COLORS.get(level, COLOR_MUTED), '!'), ('Constats prioritaires', len(findings), colors.HexColor('#7c3aed'), 'V'),
        ('Critiques', counts['Critique'], RED, 'C'), ('Élevées', counts['Élevé'], ORANGE, 'E'),
        ('Moyennes', counts['Moyen'], YELLOW, 'M'), ('Faibles', counts['Faible'], GREEN, 'F'),
        ('CVE détectées', metrics['cves'], colors.HexColor('#0891b2'), 'CVE'),
        ('Ports ouverts', metrics['port_count'], colors.HexColor('#0284c7'), 'P'),
        ('Services', metrics['service_count'], colors.HexColor('#0369a1'), 'SV'),
        ('Technologies', metrics['technology_count'], colors.HexColor('#4f46e5'), 'T'),
        ('Outils avec résultats', metrics['tool_count'], colors.HexColor('#0f766e'), 'O'),
        ('Durée totale', _format_duration(_duration(scan, results)), colors.HexColor('#475569'), 'D'),
    ]
    rows = []
    for start in range(0, len(values), 5):
        row = [_card(*item, styles) for item in values[start:start + 5]]
        rows.append(row + [''] * (5 - len(row)))
    dashboard = Table(rows, colWidths=[3.34 * cm] * 5)
    dashboard.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                   ('LEFTPADDING', (0, 0), (-1, -1), 2), ('RIGHTPADDING', (0, 0), (-1, -1), 2),
                                   ('TOPPADDING', (0, 0), (-1, -1), 3), ('BOTTOMPADDING', (0, 0), (-1, -1), 3)]))
    return dashboard


def _bars(title, entries, unavailable='Aucune donnée mesurée'):
    drawing = Drawing(460, max(92, 48 + 22 * max(1, len(entries))))
    drawing.add(String(10, drawing.height - 17, title, fontName='Helvetica-Bold', fontSize=11, fillColor=NAVY))
    if not entries:
        drawing.add(String(10, drawing.height - 43, unavailable, fontSize=9, fillColor=COLOR_MUTED))
        return drawing
    maximum = max(float(value) for _, value in entries) or 1
    for index, (label, value) in enumerate(entries[:10]):
        y = drawing.height - 43 - index * 22
        drawing.add(String(10, y + 3, str(label)[:25], fontSize=8, fillColor=NAVY))
        drawing.add(Rect(150, y, 240, 11, fillColor=colors.HexColor('#e2e8f0'), strokeColor=None))
        drawing.add(Rect(150, y, 240 * float(value) / maximum, 11, fillColor=BLUE, strokeColor=None))
        drawing.add(String(398, y + 2, str(value), fontSize=8, fillColor=COLOR_MUTED))
    return drawing


def _pie(findings, metrics):
    counts = _severity_counts(findings)
    labels = list(counts)
    values = list(counts.values())
    drawing = Drawing(460, 190)
    drawing.add(String(210, 158, 'Répartition par sévérité', fontName='Helvetica-Bold', fontSize=11, fillColor=NAVY))
    if not sum(values):
        drawing.add(String(210, 132, 'Aucune vulnérabilité significative détectée', fontSize=9, fillColor=COLOR_MUTED))
        return drawing
    pie = Pie(); pie.x, pie.y, pie.width, pie.height = 25, 20, 145, 145
    pie.data, pie.labels = values, [f'{name} ({counts[name]})' for name in labels]
    for index, name in enumerate(labels):
        pie.slices[index].fillColor = SEVERITY_COLORS[name]
    drawing.add(pie)
    drawing.add(String(210, 132, f'Total : {sum(values)}', fontSize=9, fillColor=COLOR_MUTED))
    return drawing


def _gauge(score):
    drawing = Drawing(460, 115)
    drawing.add(String(10, 94, 'Jauge du score de risque IA', fontName='Helvetica-Bold', fontSize=11, fillColor=NAVY))
    for start, end, color in ((0, 4, GREEN), (4, 7, YELLOW), (7, 9, ORANGE), (9, 10, RED)):
        drawing.add(Rect(20 + start * 40, 48, (end-start) * 40, 22, fillColor=color, strokeColor=None))
    position = 20 + min(max(score, 0), 10) * 40
    drawing.add(Rect(position - 2, 40, 4, 38, fillColor=NAVY, strokeColor=None))
    drawing.add(String(20, 22, 'Faible', fontSize=7, fillColor=GREEN)); drawing.add(String(175, 22, 'Moyen', fontSize=7, fillColor=YELLOW))
    drawing.add(String(295, 22, 'Élevé', fontSize=7, fillColor=ORANGE)); drawing.add(String(390, 22, 'Critique', fontSize=7, fillColor=RED))
    return drawing


def _interpretation(score):
    if score < 4: return 'Faible — maintenir les contrôles et la surveillance périodique.'
    if score < 7: return 'Moyen — planifier les corrections et traiter les constats les plus exposés.'
    if score < 9: return 'Élevé — engager rapidement les actions P1 et vérifier les actifs exposés.'
    return 'Critique — remédiation immédiate et validation après correction requises.'


def _tls_table(results, styles):
    observed = {}
    for item in results.get('protocols') or []:
        if isinstance(item, dict): observed[str(item.get('name', '')).replace('TLSv', 'TLS ')] = str(item.get('status', '')).lower()
    rows = [[_cell(x, styles, True) for x in ('Version TLS', 'Statut', 'Sécurité', 'Indicateur', 'Recommandation')]]
    for version in ('TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'):
        status = observed.get(version)
        if status is None: values = (version, None, None, '—', None)
        else:
            enabled = status not in ('disabled', 'rejected', 'not supported')
            if version in ('TLS 1.0', 'TLS 1.1'):
                values = (version, 'Activé' if enabled else 'Désactivé', 'Obsolète' if enabled else 'Conforme', 'X' if enabled else 'OK', 'Désactiver' if enabled else 'Maintenir désactivé')
            else:
                values = (version, 'Activé' if enabled else 'Désactivé', ('Optimal' if version == 'TLS 1.3' else 'Recommandé') if enabled else 'À améliorer', 'OK' if enabled else '!', 'Maintenir activé' if enabled else 'Activer si compatible')
        rows.append([_cell(value, styles) for value in values])
    return _table(rows, [2.7*cm, 2.7*cm, 3.1*cm, 2.3*cm, 5.9*cm])


def _protocol_chart(results):
    entries = []
    for item in results.get('protocols') or []:
        name = item.get('name', '?') if isinstance(item, dict) else str(item)
        status = item.get('status', 'inconnu') if isinstance(item, dict) else 'inconnu'
        entries.append((f'{name} ({status})', 1))
    return _bars('Protocoles SSL/TLS testés', entries, 'Aucun protocole TLS extrait')


def _certificate_metrics(results):
    data = results.get('certificates') or results.get('certificate') or results.get('ssl_certificates')
    if data is None:
        from .ssl_certificate import extract_certificate
        data = extract_certificate(str(results.get('sslscan') or ''), str(results.get('openssl') or ''))
    if data is None: return None, None
    items = data if isinstance(data, list) else [data]
    expired = sum(isinstance(x, dict) and (x.get('expired') is True or str(x.get('status', '')).lower() == 'expired') for x in items)
    return len(items), expired



def _certificate_table(results, styles):
    certificate = results.get('certificate')
    if not isinstance(certificate, dict):
        return Paragraph('Aucun certificat présenté par le serveur.', styles['CSBody'])
    status = 'Valide' if certificate.get('expired') is False else 'Expiré' if certificate.get('expired') is True else 'Présent (validité non déterminée)'
    rows = [[_cell('Propriété', styles, True), _cell('Valeur observée', styles, True)]]
    values = [
        ('Statut', status), ('Sujet', certificate.get('subject')),
        ('Émetteur', certificate.get('issuer')), ('Valide à partir du', certificate.get('not_before')),
        ('Expire le', certificate.get('not_after')),
        ('Noms alternatifs', ', '.join(certificate.get('alt_names') or [])),
        ('Algorithme de signature', certificate.get('signature_algorithm')),
        ('Taille de clé', certificate.get('key_strength')),
    ]
    rows.extend([_cell(label, styles, True), _cell(value, styles)] for label, value in values if value not in (None, '', []))
    return _table(rows, [5.2*cm, 11.5*cm])


def _cipher_table(results, styles):
    suites = extract_cipher_suites(results)
    rows = [[_cell('Protocole', styles, True), _cell('Cipher Suite', styles, True),
             _cell('Bits', styles, True), _cell('Préférence', styles, True)]]
    for suite in suites:
        if isinstance(suite, dict):
            rows.append([_cell(suite.get('protocol'), styles), _cell(suite.get('name'), styles),
                         _cell(suite.get('bits'), styles), _cell(suite.get('preference'), styles)])
        else:
            rows.append([_cell('—', styles), _cell(suite, styles), _cell('—', styles), _cell('—', styles)])
    if not suites:
        rows.append([_cell('—', styles), _cell('Aucune suite acceptée extraite de SSLScan', styles), _cell('—', styles), _cell('—', styles)])
    return _table(rows, [3*cm, 8.2*cm, 2.2*cm, 3.3*cm])

def _cipher_count(results):
    suites = extract_cipher_suites(results)
    return len(suites)


def _statistics(scan, results, findings, tools, styles, metrics):
    ports, tech = metrics['ports'], metrics['technologies']
    certificates, expired = _certificate_metrics(results)
    def first(*keys):
        return next((results[k] for k in keys if results.get(k) not in (None, '')), None)
    cwes = results.get('cwes'); cwe_count = len(cwes) if isinstance(cwes, (list, dict)) else cwes
    data = [
        ('Adresse IP', first('ip_address', 'ip', 'resolved_ip')), ('Domaine', scan.domaine),
        ('Hébergeur', first('hoster', 'hosting_provider', 'provider')), ('ASN', first('asn', 'asn_number')),
        ('Serveur Web', first('web_server', 'server')), ('Technologies détectées', metrics['technology_count']),
        ('Ports ouverts', metrics['port_count']), ('Services détectés', metrics['service_count']),
        ('Certificats analysés', certificates), ('Certificats expirés', expired),
        ('Protocoles TLS testés', metrics['tls_count']), ('Cipher Suites testées', metrics['cipher_count']),
        ('Constats prioritaires', metrics['findings']), ('CVE', metrics['cves']), ('CWE', cwe_count),
        ('Outils avec résultats', metrics['tool_count']), ('Temps total du scan', _format_duration(_duration(scan, results))),
    ]
    data = [(label, value) for label, value in data if value is not None]
    rows = [[_cell('Statistique', styles, True), _cell('Valeur', styles, True),
             _cell('Statistique', styles, True), _cell('Valeur', styles, True)]]
    half = (len(data) + 1) // 2
    for index in range(half):
        left = data[index]
        right = data[index + half] if index + half < len(data) else None
        right_cells = ([_cell(right[0], styles, True), _cell(right[1], styles)]
                       if right else [Paragraph('', styles['CSTableCell']), Paragraph('', styles['CSTableCell'])])
        rows.append([_cell(left[0], styles, True), _cell(left[1], styles), *right_cells])
    return _table(rows, [3.8*cm, 4.55*cm, 3.8*cm, 4.55*cm])


def _compliance(results):
    source = results.get('compliance') or {}
    standards = ('OWASP Top 10', 'NIST CSF', 'ISO 27001', 'PCI DSS', 'ANSSI')
    values = []
    for standard in standards:
        value = source.get(standard)
        if value is None:
            value = source.get(standard.lower().replace(' ', '_').replace('.', ''))
        if value not in (None, ''):
            values.append((standard, value))
    return values


def _compliance_scores(results):
    entries = []
    labels = {'conforme': 100, 'partiellement conforme': 50, 'non conforme': 0}
    for standard, value in _compliance(results):
        if isinstance(value, dict):
            value = value.get('score') if value.get('score') is not None else value.get('status')
        try:
            entries.append((standard, max(0, min(100, float(value)))))
        except (TypeError, ValueError):
            mapped = labels.get(str(value).lower())
            if mapped is not None:
                entries.append((standard, mapped))
    return entries

def _compliance_table(results, styles):
    rows = [[_cell('Référentiel', styles, True), _cell('Niveau', styles, True), _cell('Indicateur', styles, True)]]
    for standard, value in _compliance(results):
        if isinstance(value, dict): value = value.get('status') or value.get('score') or '—'
        if isinstance(value, (int, float)): status = 'Conforme' if value >= 80 else 'Partiellement conforme' if value >= 50 else 'Non conforme'
        else: status = str(value)
        icon = '—' if status == '—' else 'OK' if status.lower() == 'conforme' else '!' if 'partiel' in status.lower() else 'X'
        rows.append([_cell(standard, styles), _cell(status, styles), _cell(icon, styles)])
    return _table(rows, [6.2*cm, 7.2*cm, 3.3*cm])


def _posture(results, findings, styles):
    protocols = results.get('protocols') or []
    if protocols:
        secure = sum((p.get('name') not in ('TLSv1.0','TLSv1.1') and p.get('status') in ('secure','enabled')) for p in protocols if isinstance(p, dict))
        tls = round(100 * secure / len(protocols))
    else: tls = None
    certificate = results.get('certificate') or {}
    certificate_score = results.get('certificate_score')
    if certificate_score is None and certificate:
        certificate_score = 0 if certificate.get('expired') is True else 100
    values = [('TLS Security', tls), ('SSL Certificate', certificate_score), ('Web Server Configuration', results.get('web_server_score')), ('HTTP Security Headers', results.get('http_headers_score')), ('Technologies Web', results.get('technology_score')), ('Vulnérabilités', results.get('vulnerability_score')), ('Conformité', results.get('compliance_score'))]
    rows = [[_cell('Domaine de sécurité', styles, True), _cell('Score', styles, True), _cell('Posture', styles, True)]]
    for label, value in values:
        if value is None: continue
        score = max(0, min(100, round(float(value)))); bar = Drawing(230, 16)
        bar.add(Rect(0, 3, 220, 10, fillColor=colors.HexColor('#e2e8f0'), strokeColor=None))
        bar.add(Rect(0, 3, 2.2*score, 10, fillColor=GREEN if score >= 80 else YELLOW if score >= 50 else RED, strokeColor=None))
        rows.append([_cell(label, styles), _cell(f'{score} %', styles), bar])
    return _table(rows, [5.1*cm, 2.2*cm, 9.4*cm])


def _best_practices(results, styles):
    observed = {str(p.get('name','')).replace('TLSv','TLS '): str(p.get('status','')).lower() for p in results.get('protocols') or [] if isinstance(p, dict)}
    rows = [[_cell(x, styles, True) for x in ('Élément', 'État actuel', 'Bonne pratique', 'Statut')]]
    for version, expected in (('TLS 1.0','Désactivé'),('TLS 1.1','Désactivé'),('TLS 1.2','Activé'),('TLS 1.3','Activé')):
        raw = observed.get(version)
        current = None if raw is None else ('Désactivé' if raw in ('disabled','rejected','not supported') else 'Activé')
        rows.append([_cell(version, styles), _cell(current, styles), _cell(expected, styles), _cell('—' if current is None else 'OK' if current == expected else 'X', styles)])
    certs, expired = _certificate_metrics(results)
    rows.append([_cell('Certificat SSL', styles), _cell(None if certs is None else ('Expiré' if expired else 'Conforme'), styles), _cell('Valide et non expiré', styles), _cell('—' if certs is None else 'X' if expired else 'OK', styles)])
    headers = results.get('http_headers_score')
    if headers is not None:
        rows.append([_cell('En-têtes HTTP', styles), _cell(f'{headers} %', styles), _cell('Contrôles requis présents', styles), _cell('OK' if float(headers) >= 80 else '!', styles)])
    return _table(rows, [4*cm, 4*cm, 5.7*cm, 3*cm])


def _ai_box(analysis, styles):
    rows = analysis['ai_rows']
    box = _table([[_cell(label, styles, True), _cell(value, styles)] for label, value in rows], [5.2*cm, 11.5*cm], 0)
    box.setStyle(TableStyle([('BOX',(0,0),(-1,-1),1.2,BLUE),('BACKGROUND',(0,0),(0,-1),colors.HexColor('#e0f2fe'))]))
    return box


def _summary(scan, results, findings, styles):
    score = float(scan.score_risque_ia or 0); level, _ = risk_level_from_score(score)
    urgent = sum(x['severity'] in ('Critique','Élevé') for x in findings)
    recommendation = findings[0]['recommendation'] if findings else 'Maintenir les contrôles et programmer un nouveau scan.'
    rows = [[_cell('Niveau de risque', styles, True), _cell(level, styles), _cell('Actions critiques', styles, True), _cell(urgent, styles)], [_cell('Constats prioritaires', styles, True), _cell(len(findings), styles), _cell('Durée', styles, True), _cell(_format_duration(_duration(scan, results)), styles)], [_cell('Recommandation principale', styles, True), _cell(recommendation, styles), '', '']]
    table = Table(rows, colWidths=[4*cm,4.35*cm,4*cm,4.35*cm])
    table.setStyle(TableStyle([('SPAN',(1,2),(3,2)),('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#eff6ff')),('BOX',(0,0),(-1,-1),1,colors.HexColor('#2563eb')),('INNERGRID',(0,0),(-1,-1),.3,colors.HexColor('#bfdbfe')),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7)]))
    return table


def graphical_indicators(scan, results, findings, tools, styles):
    """Section compacte : 3 blocs logiques, sans graphique vide ni métrique inventée."""
    metrics = build_report_metrics(scan, results, findings)
    analysis = build_report_analysis(scan, results, findings)
    ports = metrics['ports']
    services = metrics['service_counts']
    timings = results.get('tool_timings') or results.get('timings') or {}
    timing_entries = []
    if isinstance(timings, dict):
        for tool in tools:
            value = timings.get(tool) or timings.get(tool.lower().replace(' ', '_'))
            try:
                if value is not None:
                    timing_entries.append((tool, round(float(value), 2)))
            except (TypeError, ValueError):
                continue

    primary_recommendation = (
        findings[0]['recommendation']
        if findings else 'Maintenir les contrôles actuels et programmer un nouveau scan périodique.'
    )
    legacy_tls_enabled = any(
        isinstance(protocol, dict)
        and str(protocol.get('name') or '').upper() in {'TLSV1.0', 'TLSV1.1'}
        and str(protocol.get('status') or '').lower() in {'enabled', 'supported', 'accepted'}
        for protocol in (results.get('protocols') or [])
    )
    tls_recommendation = (
        'Désactiver TLS 1.0 et TLS 1.1 et n’autoriser que TLS 1.2 ou TLS 1.3.'
        if legacy_tls_enabled
        else 'Maintenir TLS 1.0 et TLS 1.1 désactivés et privilégier TLS 1.3 lorsque les clients sont compatibles.'
    )
    certificate = results.get('certificate') or {}
    if certificate.get('expired') is True:
        certificate_recommendation = 'Renouveler immédiatement le certificat expiré et vérifier le déploiement de la chaîne complète.'
    elif certificate:
        certificate_recommendation = 'Surveiller la date d’expiration du certificat et automatiser son renouvellement avant échéance.'
    else:
        certificate_recommendation = 'Installer un certificat SSL valide et vérifier que sa chaîne de confiance est complète.'

    flowables = [
        Paragraph('Vue d’ensemble', styles['CSHeading']),
        _kpis(scan, results, findings, tools, styles, metrics),
        _table_recommendation('Traiter en priorité les indicateurs critiques ou élevés et suivre leur évolution après correction.', styles),
        Spacer(1, 5),
        _summary(scan, results, findings, styles),
        _table_recommendation(primary_recommendation, styles),
        Spacer(1, 6),
        PageBreak(),
        Paragraph('Sécurité SSL/TLS et exposition réseau', styles['CSHeading']),
        _tls_table(results, styles),
        _table_recommendation(tls_recommendation, styles),
        Spacer(1, 6),
        Paragraph('Certificat SSL observé', styles['CSHeading']),
        _certificate_table(results, styles),
        _table_recommendation(certificate_recommendation, styles),
        Spacer(1, 6),
        Paragraph('Cipher Suites acceptées par SSLScan', styles['CSHeading']),
        _cipher_table(results, styles),
        _table_recommendation('Désactiver les suites cryptographiques faibles ou obsolètes et conserver uniquement des algorithmes modernes.', styles),
        Spacer(1, 6),
        _protocol_chart(results),
    ]

    # Les graphiques réseau ne sont affichés que si Nmap a réellement produit des données.
    if results.get('nmap'):
        flowables.extend([
            _bars('Ports ouverts', [(f"{port['port']}/{port['protocol']} {port['service']}", 1) for port in ports],
                  'Aucun port ouvert détecté'),
            _bars('Services détectés', sorted(services.items(), key=lambda item: (-item[1], item[0])),
                  'Aucun service détecté'),
        ])

    flowables.extend([
        Spacer(1, 8),
        Paragraph('Statistiques techniques calculées', styles['CSHeading']),
        _statistics(scan, results, findings, tools, styles, metrics),
        _table_recommendation('Comparer ces statistiques entre les scans successifs afin de confirmer la réduction de la surface d’attaque.', styles),
    ])
    if timing_entries:
        flowables.extend([
            Spacer(1, 6),
            _bars("Temps d'exécution par outil (secondes)", timing_entries),
        ])

    flowables.extend([
        Spacer(1, 8),
        Paragraph('Analyse IA', styles['CSHeading']),
        _ai_box(analysis, styles),
        _table_recommendation(primary_recommendation, styles),
        Spacer(1, 8),
        Paragraph('Posture de sécurité', styles['CSHeading']),
        _posture(results, findings, styles),
        _table_recommendation('Renforcer en priorité les domaines dont le score est le plus faible, puis mesurer à nouveau leur posture.', styles),
        Spacer(1, 8),
        Paragraph('Bonnes pratiques et conformité', styles['CSHeading']),
        _best_practices(results, styles),
        _table_recommendation('Corriger chaque écart signalé, documenter la configuration cible et vérifier la conformité après déploiement.', styles),
    ])
    if results.get('compliance'):
        flowables.extend([
            Spacer(1, 8),
            _compliance_table(results, styles),
            _table_recommendation('Établir un plan de mise en conformité pour chaque référentiel incomplet ou non conforme.', styles),
        ])
    compliance_scores = _compliance_scores(results)
    if compliance_scores:
        flowables.extend([Spacer(1, 6), _bars('Niveau de conformité (%)', compliance_scores)])
    return flowables
