"""
Génération automatique de rapports PDF professionnels CyberScan.

Utilise le modèle Scan existant et enregistre un objet Rapport (chemin_pdf).
Ne modifie aucune logique de scan.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    Image,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .models import Rapport, Scan
from .cve_data import collect_scan_cves
from .report_data import tool_names_with_results
from .risk_policy import level_from_score, normalize_score

logger = logging.getLogger(__name__)

# Couleurs charte CyberScan
COLOR_PRIMARY = colors.HexColor('#0f172a')
COLOR_ACCENT = colors.HexColor('#0ea5e9')
COLOR_CRITICAL = colors.HexColor('#dc2626')
COLOR_HIGH = colors.HexColor('#ea580c')
COLOR_MEDIUM = colors.HexColor('#ca8a04')
COLOR_LOW = colors.HexColor('#16a34a')
COLOR_MUTED = colors.HexColor('#64748b')
COLOR_LIGHT_BG = colors.HexColor('#f1f5f9')
COLOR_WHITE = colors.white

MAX_RAW_CHARS = 3500


def risk_level_from_score(score: Optional[float]) -> Tuple[str, colors.Color]:
    """Retourne le libellé et la couleur issus de la politique de risque unique."""
    if score is None:
        return 'Inconnu', COLOR_MUTED
    level = level_from_score(score)
    return level, {
        'Critique': COLOR_CRITICAL, 'Élevé': COLOR_HIGH,
        'Moyen': COLOR_MEDIUM, 'Faible': COLOR_LOW,
    }[level]


def security_score_from_risk(risk_score: Optional[float]) -> float:
    """Score global de sécurité (0–10) = inverse du score de risque."""
    if risk_score is None:
        return 0.0
    return round(max(0.0, min(10.0, 10.0 - float(risk_score))), 1)


def _reports_dir() -> Path:
    """Return the PDF output directory, creating it if needed.

    Docker bind-mounts often replace ``/app/media`` with a host folder that may
    be missing ``rapports/``. Create both MEDIA_ROOT and REPORTS_DIR explicitly
    so PDF generation does not fail with FileNotFoundError.
    """
    base = Path(getattr(settings, 'MEDIA_ROOT', Path(settings.BASE_DIR) / 'media'))
    reports = Path(getattr(settings, 'REPORTS_DIR', base / 'rapports'))
    try:
        base.mkdir(parents=True, exist_ok=True)
        reports.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"Impossible de créer le dossier des rapports PDF ({reports}): {exc}. "
            "Vérifiez que le volume media est monté et accessible en écriture."
        ) from exc
    if not os.access(reports, os.W_OK):
        raise RuntimeError(
            f"Le dossier des rapports PDF n'est pas accessible en écriture: {reports}"
        )
    return reports


def _logo_path() -> Optional[str]:
    candidates = [
        Path(settings.BASE_DIR) / 'scanner' / 'static' / 'scanner' / 'cyberscan_logo.png',
        Path(__file__).resolve().parent / 'static' / 'scanner' / 'cyberscan_logo.png',
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def _escape(text: Any) -> str:
    if text is None:
        return ''
    s = str(text)
    s = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    # reportlab Paragraph: newlines -> <br/>
    s = s.replace('\r\n', '\n').replace('\r', '\n')
    return s


def _truncate(text: str, limit: int = MAX_RAW_CHARS) -> str:
    text = text or ''
    if len(text) <= limit:
        return text
    return text[:limit] + '\n\n[… sortie tronquée pour lisibilité du rapport …]'


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='CSTitle',
        parent=styles['Title'],
        fontSize=20,
        textColor=COLOR_PRIMARY,
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
    ))
    styles.add(ParagraphStyle(
        name='CSSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=COLOR_MUTED,
        alignment=TA_CENTER,
        spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name='CSHeading',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=COLOR_PRIMARY,
        spaceBefore=14,
        spaceAfter=8,
        fontName='Helvetica-Bold',
        borderPadding=3,
    ))
    styles.add(ParagraphStyle(
        name='CSBody',
        parent=styles['Normal'],
        fontSize=9.5,
        leading=13,
        textColor=COLOR_PRIMARY,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name='CSMono',
        parent=styles['Code'],
        fontSize=7.5,
        leading=9.5,
        fontName='Courier',
        textColor=COLOR_PRIMARY,
        backColor=COLOR_LIGHT_BG,
        leftIndent=4,
        rightIndent=4,
        spaceBefore=4,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name='CSSmall',
        parent=styles['Normal'],
        fontSize=8,
        textColor=COLOR_MUTED,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name='CSBullet',
        parent=styles['Normal'],
        fontSize=9.5,
        leading=12,
        leftIndent=12,
        textColor=COLOR_PRIMARY,
        spaceAfter=3,
    ))
    styles.add(ParagraphStyle(
        name='CSTableCell',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11,
        textColor=COLOR_PRIMARY,
    ))
    return styles


def _header_footer(canvas, doc):
    canvas.saveState()
    page_w, page_h = A4
    # Bandeau bas
    canvas.setFillColor(COLOR_PRIMARY)
    canvas.rect(0, 0, page_w, 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(COLOR_WHITE)
    canvas.setFont('Helvetica', 8)
    canvas.drawString(15 * mm, 7 * mm, 'CyberScan — Rapport confidentiel')
    if not getattr(canvas, '_cyberscan_total_pagination', False):
        canvas.drawRightString(page_w - 15 * mm, 7 * mm, f'Page {doc.page}')
    # Ligne accent haut
    canvas.setStrokeColor(COLOR_ACCENT)
    canvas.setLineWidth(2)
    canvas.line(15 * mm, page_h - 12 * mm, page_w - 15 * mm, page_h - 12 * mm)
    canvas.restoreState()


def _section_title(styles, title: str):
    return Paragraph(f'▸ {_escape(title)}', styles['CSHeading'])


def _raw_block(styles, raw: str) -> List:
    raw = _truncate(raw or 'Aucune donnée disponible.')
    # Split long mono blocks into paragraphs for ReportLab stability
    lines = _escape(raw).split('\n')
    chunks = []
    buf = []
    for line in lines:
        buf.append(line)
        if len(buf) >= 40:
            chunks.append(Paragraph('<br/>'.join(buf), styles['CSMono']))
            buf = []
    if buf:
        chunks.append(Paragraph('<br/>'.join(buf), styles['CSMono']))
    if not chunks:
        chunks.append(Paragraph('—', styles['CSMono']))
    return chunks


def _info_table(rows: List[Tuple[str, str]], styles) -> Table:
    data = [
        [
            Paragraph(f'<b>{_escape(k)}</b>', styles['CSTableCell']),
            Paragraph(_escape(v), styles['CSTableCell']),
        ]
        for k, v in rows
    ]
    table = Table(data, colWidths=[5.2 * cm, 11.5 * cm])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), COLOR_LIGHT_BG),
        ('BACKGROUND', (1, 0), (1, -1), COLOR_WHITE),
        ('BOX', (0, 0), (-1, -1), 0.5, COLOR_MUTED),
        ('INNERGRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    return table


def _build_executive_summary(scan: Scan, resultats: dict, cves, security_score: float, risk_label: str) -> str:
    # QuerySet.count() vs list: list also has .count(value), so prefer len() for sequences.
    try:
        n_cves = cves.count() if not isinstance(cves, (list, tuple)) else len(cves)
    except TypeError:
        n_cves = len(cves)
    protocols = resultats.get('protocols') or []
    vulns = resultats.get('vulnerabilities') or []
    zap = resultats.get('zap_findings') or []
    nuclei = resultats.get('nuclei_findings') or []
    whatweb = (resultats.get('whatweb') or {}).get('technologies') or []
    nvd_count = (resultats.get('nvd') or {}).get('cves_count', 0) or len(resultats.get('nvd_cves') or [])

    parts = [
        f"Ce rapport présente les résultats de l'audit de sécurité automatisé "
        f"réalisé par CyberScan sur le domaine « {scan.domaine} » "
        f"le {scan.date_scan.strftime('%d/%m/%Y à %H:%M')} (UTC).",
        f"Le score global de sécurité est estimé à {security_score}/10, "
        f"correspondant à un niveau de risque « {risk_label} » "
        f"(score de risque IA : {scan.score_risque_ia}/10).",
        f"Synthèse : {n_cves} CVE référencée(s), {len(vulns)} indicateur(s) SSL/TLS, "
        f"{len(protocols)} protocole(s) détecté(s), {len(whatweb)} technologie(s) web, "
        f"{len(zap)} alerte(s) OWASP ZAP, {len(nuclei)} constat(s) Nuclei, "
        f"{nvd_count} résultat(s) NVD.",
    ]
    if scan.score_risque_ia >= 7:
        parts.append(
            "Des vulnérabilités critiques ou un score de risque élevé nécessitent "
            "une remédiation prioritaire. Consultez les sections CVE et Recommandations."
        )
    elif scan.score_risque_ia >= 4:
        parts.append(
            "Des points d'attention ont été identifiés. Un plan de remédiation "
            "à court/moyen terme est recommandé."
        )
    else:
        parts.append(
            "Le profil de risque global est relativement faible. "
            "Maintenez les bonnes pratiques et un suivi régulier des mises à jour."
        )
    return ' '.join(parts)


def _collect_tools_used(resultats: dict) -> List[str]:
    return tool_names_with_results(resultats)

def _build_remediation_plan(scan: Scan, resultats: dict, recommendations: List[str]) -> List[Dict[str, str]]:
    """Plan de correction priorisé pour le rapport PDF."""
    plan: List[Dict[str, str]] = []

    for cve in collect_scan_cves(scan, resultats):
        score = float(cve.get('cvss_score') or 0)
        if score >= 7:
            priorite = 'Immédiate (P1)'
        elif score >= 4:
            priorite = 'Court terme (P2)'
        else:
            priorite = 'Moyen terme (P3)'
        action = (cve.get('recommendation') or "Appliquer le correctif indiqué dans la fiche NVD enregistrée.").strip()
        plan.append({
            'priorite': priorite,
            'element': cve['cve_id'],
            'action': action,
        })
    for finding in resultats.get('zap_findings') or []:
        risk = (finding.get('risk') or '').lower()
        if risk in ('high', 'medium'):
            priorite = 'Immédiate (P1)' if risk == 'high' else 'Court terme (P2)'
            sol = (finding.get('solution') or finding.get('description') or '').strip()
            plan.append({
                'priorite': priorite,
                'element': finding.get('name', 'Alerte ZAP'),
                'action': sol[:500] if sol else 'Corriger selon les recommandations OWASP ZAP.',
            })

    for finding in resultats.get('nuclei_findings') or []:
        severity = str(finding.get('severity') or '').lower()
        if severity not in ('critical', 'high', 'medium'):
            continue
        priorite = {
            'critical': 'Immédiate (P1)',
            'high': 'Immédiate (P1)',
            'medium': 'Court terme (P2)',
        }[severity]
        plan.append({
            'priorite': priorite,
            'element': finding.get('template_id') or finding.get('name') or 'Constat Nuclei',
            'action': (finding.get('remediation') or (
                'Valider le constat Nuclei, corriger le composant ou la configuration concernée, '
                'puis relancer le template pour confirmer la remédiation.'
            ))[:500],
        })

    for vuln in resultats.get('vulnerabilities') or []:
        if vuln in ('TLSv1.0', 'TLSv1.1', 'WEAK_CIPHER'):
            plan.append({
                'priorite': 'Immédiate (P1)',
                'element': str(vuln),
                'action': 'Mettre à jour la configuration TLS et désactiver les protocoles/chiffrements obsolètes.',
            })

    if not plan and recommendations:
        for i, rec in enumerate(recommendations[:5], 1):
            plan.append({
                'priorite': f'Suivi (P{i})',
                'element': 'Recommandation générale',
                'action': rec,
            })

    if not plan:
        plan.append({
            'priorite': 'Maintenance',
            'element': 'Configuration globale',
            'action': 'Maintenir les mises à jour et planifier des scans périodiques.',
        })
    return plan


def _collect_recommendations(scan: Scan, resultats: dict) -> List[str]:
    recs: List[str] = []
    seen = set()

    for cve in collect_scan_cves(scan, resultats):
        recommendation = (cve.get('recommendation') or '').strip()
        if recommendation and recommendation not in seen:
            seen.add(recommendation)
            recs.append(f"[{cve['cve_id']}] {recommendation}")
    for finding in resultats.get('zap_findings') or []:
        sol = (finding.get('solution') or '').strip()
        name = finding.get('name') or 'Alerte ZAP'
        if sol and sol not in seen:
            seen.add(sol)
            recs.append(f"[ZAP — {name}] {sol}")
    for finding in resultats.get('nuclei_findings') or []:
        remediation = (finding.get('remediation') or '').strip()
        if remediation and remediation not in seen:
            seen.add(remediation)
            name = finding.get('template_id') or finding.get('name') or 'Nuclei'
            recs.append(f"[Nuclei — {name}] {remediation}")

    vulns = resultats.get('vulnerabilities') or []
    if 'TLSv1.0' in vulns or 'TLSv1.1' in vulns:
        msg = 'Désactiver TLSv1.0/TLSv1.1 et n’autoriser que TLSv1.2 et TLSv1.3.'
        if msg not in seen:
            seen.add(msg)
            recs.append(msg)
    if 'WEAK_CIPHER' in vulns:
        msg = 'Retirer les suites de chiffrement faibles (3DES, RC4) au profit d’AES-GCM ou ChaCha20-Poly1305.'
        if msg not in seen:
            seen.add(msg)
            recs.append(msg)

    if not recs:
        recs.append(
            'Aucune recommandation critique générée. Poursuivre le monitoring '
            'et planifier des scans périodiques.'
        )
    return recs


def _format_whatweb(resultats: dict) -> str:
    ww = resultats.get('whatweb') or {}
    if not ww.get('success') and not ww.get('technologies'):
        err = ww.get('error') or 'WhatWeb non disponible ou échec d’exécution.'
        return err
    techs = ww.get('technologies') or []
    if not techs:
        return 'Aucune technologie web détectée.'
    lines = []
    for t in techs[:80]:
        name = t.get('name', '?')
        versions = t.get('version') or []
        strings = t.get('string') or []
        extra = []
        if versions:
            extra.append('v=' + ', '.join(str(v) for v in versions[:5]))
        if strings:
            extra.append(', '.join(str(s) for s in strings[:3]))
        suffix = f" ({'; '.join(extra)})" if extra else ''
        lines.append(f"• {name}{suffix}")
    return '\n'.join(lines)


def _format_zap(resultats: dict) -> str:
    if resultats.get('zap_success') is False and not resultats.get('zap_findings'):
        return resultats.get('zap_error') or 'Scan ZAP non disponible ou désactivé.'
    findings = resultats.get('zap_findings') or []
    if not findings:
        return 'Aucune alerte OWASP ZAP détectée.'
    lines = []
    for f in findings[:60]:
        lines.append(
            f"• [{f.get('risk', '?')}] {f.get('name', 'Alerte')} — "
            f"{f.get('url', '')} (×{f.get('count', 1)})\n"
            f"  { (f.get('description') or '')[:300] }"
        )
    return '\n'.join(lines)


def _format_nvd(resultats: dict) -> str:
    nvd_meta = resultats.get('nvd') or {}
    nvd_cves = resultats.get('nvd_cves') or []
    lines = [
        f"Statut NVD : {'OK' if nvd_meta.get('success', True) else 'Erreur'}",
        f"Nombre de CVE NVD : {nvd_meta.get('cves_count', len(nvd_cves))}",
    ]
    errors = nvd_meta.get('errors') or []
    if errors:
        lines.append('Erreurs : ' + '; '.join(str(e) for e in errors[:5]))
    if not nvd_cves:
        lines.append('Aucun CVE NVD associé aux technologies détectées (ou NVD non activé).')
    else:
        for c in nvd_cves[:40]:
            lines.append(
                f"• {c.get('cve_id', '?')} — CVSS {c.get('cvss_score', 'N/A')} "
                f"({c.get('severity', '')}) — {(c.get('description') or '')[:200]}"
            )
    return '\n'.join(lines)


def _format_ssllabs(resultats: dict) -> str:
    data = resultats.get('ssllabs') or resultats.get('ssl_labs') or {}
    if not data:
        return (
            'SSL Labs non inclus dans ce scan. '
            'Les résultats SSL Labs apparaîtront ici lorsqu’ils seront présents '
            'dans resultats_ssl["ssllabs"].'
        )
    if isinstance(data, str):
        return data
    grade = data.get('grade', 'N/A')
    status = data.get('status', 'N/A')
    host = data.get('host', '')
    err = data.get('error')
    parts = [f'Hôte : {host}', f'Statut : {status}', f'Note (grade) : {grade}']
    if err:
        parts.append(f'Erreur : {err}')
    return '\n'.join(parts)


def build_report_context(scan: Scan) -> Dict[str, Any]:
    """Construit un dict structuré pour l’API de consultation du rapport."""
    resultats = scan.resultats_ssl or {}
    cve_list = collect_scan_cves(scan, resultats)
    risk_label, _ = risk_level_from_score(scan.score_risque_ia)
    security_score = security_score_from_risk(scan.score_risque_ia)
    summary = _build_executive_summary(scan, resultats, cve_list, security_score, risk_label)
    recommendations = _collect_recommendations(scan, resultats)

    avg_cvss = (
        round(sum(float(cve['cvss_score']) for cve in cve_list) / len(cve_list), 1)
        if cve_list else 0.0
    )

    return {
        'scan_id': scan.id,
        'domaine': scan.domaine,
        'date_scan': scan.date_scan.isoformat() if scan.date_scan else None,
        'score_global_securite': security_score,
        'score_risque_ia': scan.score_risque_ia,
        'niveau_risque': risk_label,
        'resume_executif': summary,
        'sslscan': resultats.get('sslscan') or '',
        'openssl': resultats.get('openssl') or '',
        'nmap': resultats.get('nmap') or '',
        'whatweb': resultats.get('whatweb') or {},
        'zap_findings': resultats.get('zap_findings') or [],
        'zap_success': resultats.get('zap_success'),
        'zap_error': resultats.get('zap_error'),
        'nuclei_findings': resultats.get('nuclei_findings') or [],
        'nuclei_requested': resultats.get('nuclei_requested', False),
        'nuclei_success': resultats.get('nuclei_success'),
        'nuclei_error': resultats.get('nuclei_error'),
        'ssllabs': resultats.get('ssllabs') or resultats.get('ssl_labs') or {},
        'nvd': resultats.get('nvd') or {},
        'nvd_cves': resultats.get('nvd_cves') or [],
        'cves': cve_list,
        'score_cvss_moyen': avg_cvss,
        'recommandations': recommendations,
        'protocols': resultats.get('protocols') or [],
        'vulnerabilities': resultats.get('vulnerabilities') or [],
        'outils_utilises': _collect_tools_used(resultats),
        'plan_correction': _build_remediation_plan(scan, resultats, recommendations),
    }


def build_json_export(scan: Scan) -> Dict[str, Any]:
    """Payload JSON pour GET /api/scans/<id>/export/json/."""
    context = build_report_context(scan)
    resultats = scan.resultats_ssl or {}
    ww = resultats.get('whatweb') or {}
    return {
        'domaine': scan.domaine,
        'date': scan.date_scan.isoformat() if scan.date_scan else None,
        'score_ia': scan.score_risque_ia,
        'protocoles': context.get('protocols') or [],
        'vulnerabilites': context.get('vulnerabilities') or [],
        'technologies': ww.get('technologies') or [],
        'cve': context.get('cves') or [],
        'vulnerabilites_nuclei': context.get('nuclei_findings') or [],
        'recommandations': context.get('recommandations') or [],
        'outils_utilises': context.get('outils_utilises') or [],
    }


def generate_pdf_for_scan(scan: Scan, force_regenerate: bool = False) -> Rapport:
    from .report_fixed import generate_fixed_pdf_for_scan
    return generate_fixed_pdf_for_scan(scan, force_regenerate=force_regenerate)

def resolve_pdf_absolute_path(rapport: Rapport) -> Path:
    """Résout le chemin absolu du fichier PDF d’un Rapport."""
    raw = Path(rapport.chemin_pdf)
    if raw.is_file():
        return raw
    media_root = Path(getattr(settings, 'MEDIA_ROOT', settings.BASE_DIR / 'media'))
    candidate = media_root / rapport.chemin_pdf
    if candidate.is_file():
        return candidate
    # Fallback : reports dir + basename
    candidate2 = _reports_dir() / raw.name
    return candidate2
