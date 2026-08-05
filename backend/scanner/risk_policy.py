"""Politique unique de classification du risque CyberScan."""
from __future__ import annotations

RISK_THRESHOLDS = {"critical": 9.0, "high": 7.0, "medium": 4.0}


def normalize_score(value):
    try:
        return round(max(0.0, min(10.0, float(value))), 1)
    except (TypeError, ValueError):
        return 0.0


def level_from_score(value):
    score = normalize_score(value)
    if score >= RISK_THRESHOLDS["critical"]:
        return "Critique"
    if score >= RISK_THRESHOLDS["high"]:
        return "Élevé"
    if score >= RISK_THRESHOLDS["medium"]:
        return "Moyen"
    return "Faible"


def priority_from_score(value):
    score = normalize_score(value)
    if score >= RISK_THRESHOLDS["high"]:
        return {"code": "P1", "label": "Immédiate"}
    if score >= RISK_THRESHOLDS["medium"]:
        return {"code": "P2", "label": "Court terme"}
    return {"code": "P3", "label": "Planifiée"}


def recommendation_order(findings):
    """Ordre stable : priorité, CVSS décroissant, identifiant."""
    rank = {"P1": 0, "P2": 1, "P3": 2}
    return sorted(
        findings,
        key=lambda item: (
            rank.get(item.get("priority_code"), 3),
            -normalize_score(item.get("score")),
            str(item.get("id") or item.get("source_id") or item.get("component") or ""),
        ),
    )