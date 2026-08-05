"""Sections narratives déterministes construites uniquement depuis le scan."""
from __future__ import annotations

from .report_data import build_report_metrics, tool_execution_issues
from .risk_policy import level_from_score, normalize_score, priority_from_score, recommendation_order


def _joined(values, empty):
    cleaned = [str(value).strip() for value in values if str(value).strip()]
    return ", ".join(dict.fromkeys(cleaned)) if cleaned else empty


def build_report_analysis(scan, results, findings):
    ordered = recommendation_order(findings)
    metrics = build_report_metrics(scan, results, ordered)
    score = normalize_score(scan.score_risque_ia)
    level = level_from_score(score)
    overall_priority = priority_from_score(score)
    severity = metrics["severity"]
    certificate = results.get("certificate") or {}
    execution_issues = tool_execution_issues(results)

    observed_parts = [
        f"Score IA {score:.1f}/10 ({level})",
        f"{metrics['findings']} vulnérabilité(s)",
        f"{severity['Critique']} critique(s), {severity['Élevé']} élevée(s), "
        f"{severity['Moyen']} moyenne(s), {severity['Faible']} faible(s)",
        f"{metrics['cves']} CVE",
        f"{metrics['port_count']} port(s) ouvert(s) et {metrics['service_count']} service(s)",
        f"{metrics['technology_count']} technologie(s)",
        f"{metrics['tool_count']} outil(s) avec résultats",
        f"{metrics['tls_count']} version(s) TLS et {metrics['cipher_count']} suite(s) de chiffrement",
    ]
    if certificate:
        certificate_state = "expiré" if certificate.get("expired") is True else "valide" if certificate.get("expired") is False else "présent"
        observed_parts.append(f"certificat {certificate_state}")
    if execution_issues:
        observed_parts.append(f"couverture partielle ({len(execution_issues)} outil(s) en échec)")

    summary = f"Analyse de {scan.domaine} : " + "; ".join(observed_parts) + "."
    top = ordered[:3]
    ai_rows = [
        (
            "Score et niveau",
            f"{score:.1f}/10 — {level}"
            + (" — aucun signal de risque détecté" if score == 0 and not ordered else ""),
        ),
        ("Répartition observée", f"Critiques {severity['Critique']} | Élevées {severity['Élevé']} | Moyennes {severity['Moyen']} | Faibles {severity['Faible']}"),
        ("Constats prioritaires", _joined((item["component"] for item in top), "Aucun constat de vulnérabilité détecté")),
        ("Sources analysées", _joined(metrics["tools"], "Aucun scanner n’a retourné de résultat")),
        (
            "Couverture du scan",
            "Partielle — " + "; ".join(f"{item['tool']}: {item['detail']}" for item in execution_issues)
            if execution_issues else "Complète pour les outils activés",
        ),
        ("Priorité globale", f"{overall_priority['code']} — {overall_priority['label']}"),
    ]
    if score == 0 and not ordered:
        ai_rows.append((
            "Interprétation",
            "Le score 0.0 signifie qu’aucun signal de risque positif n’a été détecté "
            "dans les résultats reçus; il ne signifie pas qu’aucun outil n’a été exécuté.",
        ))
    if top:
        ai_rows.append(("Recommandation principale", top[0]["recommendation"]))

    plan = [
        {
            "priority_code": item["priority_code"],
            "priority": item["priority"],
            "id": item["id"],
            "component": item["component"],
            "recommendation": item["recommendation"],
            "evidence": item["evidence"],
            "score": item["score"],
            "severity": item["severity"],
        }
        for item in ordered
    ]
    for index, issue in enumerate(execution_issues, 1):
        plan.append({
            "priority_code": "P2",
            "priority": "Court terme",
            "id": f"SCAN-COVERAGE-{index:03d}",
            "component": issue["tool"],
            "recommendation": (
                f"Relancer {issue['tool']} et intégrer son résultat avant de considérer "
                "la couverture du scan comme complète."
            ),
            "evidence": issue["detail"],
            "score": 0.0,
            "severity": "Information",
        })

    legacy_tls_enabled = any(
        str(protocol.get("name") or "").upper() in {"TLSV1.0", "TLSV1.1"}
        and str(protocol.get("status") or "").lower() in {"enabled", "supported", "accepted"}
        for protocol in (results.get("protocols") or [])
        if isinstance(protocol, dict)
    )
    certificate_valid = (
        certificate.get("expired") is False
        or str(certificate.get("status") or "").lower() == "valid"
    )
    https_available = any(
        str(port.get("port") or "") == "443"
        and str(port.get("service") or "").lower() == "https"
        and str(port.get("state") or "open").lower() == "open"
        for port in (metrics.get("ports") or [])
        if isinstance(port, dict)
    )

    tls_conclusion = legacy_tls_enabled and certificate_valid and https_available
    if tls_conclusion:
        conclusion = (
            f"Selon CyberScan, le niveau de risque {level.lower()} vient principalement d’une "
            "configuration TLS trop permissive. Le certificat SSL est valide et le service HTTPS "
            "fonctionne correctement, mais le serveur accepterait encore des protocoles et des "
            "algorithmes anciens."
        )
    elif ordered:
        top_ids = _joined((item["id"] for item in top), "")
        conclusion = (
            f"Le scan de {scan.domaine} établit un risque {level.lower()} ({score:.1f}/10) "
            f"à partir de {metrics['findings']} constat(s) documenté(s). "
            f"La priorité {overall_priority['code']} concerne {top_ids}. "
            f"Après application des {len(ordered)} action(s) associée(s), un nouveau scan devra mesurer le résultat."
        )
    else:
        conclusion = (
            f"Le scan de {scan.domaine} établit un risque {level.lower()} ({score:.1f}/10) "
            "sans vulnérabilité significative extraite des résultats disponibles."
        )
    if execution_issues and not tls_conclusion:
        conclusion += (
            " La couverture reste partielle car "
            + ", ".join(item["tool"] for item in execution_issues)
            + " n’a pas retourné un résultat exploitable; ces outils doivent être relancés."
        )
    return {
        "score": score,
        "level": level,
        "overall_priority": overall_priority,
        "metrics": metrics,
        "summary": summary,
        "ai_rows": ai_rows,
        "plan": plan,
        "conclusion": conclusion,
        "execution_issues": execution_issues,
    }