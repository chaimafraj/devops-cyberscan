"""Normalisation et fusion déterministes des CVE du pipeline CyberScan."""
from __future__ import annotations

import re
from typing import Any, Iterable


CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"


def normalize_cve_id(value: Any) -> str:
    candidate = str(value or "").strip().upper()
    return candidate if CVE_ID_RE.fullmatch(candidate) else ""


def nvd_url_for(cve_id: Any) -> str:
    normalized = normalize_cve_id(cve_id)
    return NVD_DETAIL_URL.format(cve_id=normalized) if normalized else ""


def _value(record: Any, *names: str, default: Any = "") -> Any:
    if isinstance(record, dict):
        for name in names:
            value = record.get(name)
            if value not in (None, "", [], {}):
                return value
        return default
    for name in names:
        value = getattr(record, name, None)
        if value not in (None, "", [], {}):
            return value
    return default


def _product_labels(record: Any) -> list[str]:
    direct = _value(
        record,
        "produit_concerne",
        "product",
        "affected_product",
        "component",
    )
    labels: list[str] = []
    if direct:
        values = direct if isinstance(direct, (list, tuple, set)) else [direct]
        labels.extend(str(value).strip() for value in values if str(value).strip())

    products = _value(record, "products", "technologies", default=[])
    values = products if isinstance(products, (list, tuple, set)) else [products]
    for value in values:
        if isinstance(value, dict):
            name = str(value.get("name") or "").strip()
            versions = value.get("version") or []
            versions = versions if isinstance(versions, list) else [versions]
            version_text = ", ".join(str(item).strip() for item in versions if str(item).strip())
            label = " ".join(part for part in (name, version_text) if part)
        else:
            label = str(value).strip()
        if label:
            labels.append(label)
    return list(dict.fromkeys(labels))


def normalize_cve_record(record: Any) -> dict[str, Any] | None:
    """Retourne les cinq champs CVE obligatoires, sans accepter un identifiant non-CVE."""
    cve_id = normalize_cve_id(_value(record, "cve_id", "id"))
    if not cve_id:
        return None

    try:
        cvss_score = max(0.0, min(10.0, float(_value(record, "cvss_score", "score", default=0) or 0)))
    except (TypeError, ValueError):
        cvss_score = 0.0

    products = _product_labels(record)
    supplied_url = str(_value(record, "lien_nvd", "nvd_url", default="") or "").strip()
    nvd_url = supplied_url if supplied_url.startswith("https://nvd.nist.gov/vuln/detail/") else nvd_url_for(cve_id)
    recommendation = str(_value(record, "recommendation", "recommandation_ia", default="") or "").strip()
    description = str(_value(record, "description", default="") or "").strip()
    published_date = str(_value(record, "published_date", default="") or "").strip()

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "description": description,
        "produit_concerne": ", ".join(products),
        "lien_nvd": nvd_url,
        "recommendation": recommendation,
        "recommandation_ia": recommendation,
        "published_date": published_date,
    }


def _merge_value(current: dict[str, Any], incoming: dict[str, Any], key: str) -> None:
    if current.get(key) in (None, "", [], {}) and incoming.get(key) not in (None, "", [], {}):
        current[key] = incoming[key]


def merge_cve_records(records: Iterable[Any]) -> list[dict[str, Any]]:
    """Fusionne les sources sans écraser une donnée réelle par une valeur vide."""
    merged: dict[str, dict[str, Any]] = {}
    for raw in records:
        item = normalize_cve_record(raw)
        if item is None:
            continue
        current = merged.setdefault(item["cve_id"], dict(item))
        for key in (
            "description",
            "produit_concerne",
            "lien_nvd",
            "recommendation",
            "recommandation_ia",
            "published_date",
        ):
            _merge_value(current, item, key)
        if not current.get("cvss_score") and item.get("cvss_score"):
            current["cvss_score"] = item["cvss_score"]

    return sorted(
        merged.values(),
        key=lambda item: (-float(item.get("cvss_score") or 0), item["cve_id"]),
    )


def collect_scan_cves(scan: Any, results: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Source unique des CVE pour API, statistiques, IA, Excel et PDF."""
    records: list[Any] = []
    source = results if isinstance(results, dict) else {}
    sslscan_raw = ANSI_RE.sub("", str(source.get("sslscan") or ""))
    try:
        for raw in scan.cves.all():
            item = normalize_cve_record(raw)
            if item is None:
                continue
            description = item["description"].casefold()
            # L'ancienne version associait TLS 1.0 à POODLE. Cette association
            # historique n'est conservée que si SSLScan prouve SSLv3 activé.
            legacy_poodle = (
                item["cve_id"] == "CVE-2014-3566"
                and "tlsv1.0" in description
                and "poodle" in description
            )
            if legacy_poodle and not re.search(r"(?mi)^\s*SSLv3\s+enabled\s*$", sslscan_raw):
                continue
            # Pour l'association SWEET32 historique, le produit est récupéré
            # de la ligne 3DES réellement enregistrée par SSLScan.
            if (
                item["cve_id"] == "CVE-2016-2183"
                and not item["produit_concerne"]
                and re.search(r"(?:3DES|DES-CBC3)", sslscan_raw, re.IGNORECASE)
            ):
                item["produit_concerne"] = "Suites TLS Triple-DES acceptées"
            records.append(item)
    except (AttributeError, TypeError):
        pass
    records.extend(item for item in source.get("nvd_cves") or [] if isinstance(item, dict))
    return merge_cve_records(records)

def cve_model_values(record: Any) -> dict[str, Any] | None:
    item = normalize_cve_record(record)
    if item is None:
        return None
    return {
        "cve_id": item["cve_id"],
        "description": item["description"],
        "cvss_score": round(float(item["cvss_score"]), 1),
        "recommandation_ia": item["recommendation"],
        "produit_concerne": item["produit_concerne"],
        "lien_nvd": item["lien_nvd"],
    }
