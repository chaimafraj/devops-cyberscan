"""Construction unique des données persistées à la fin d'un scan."""
from __future__ import annotations

from typing import Any

from .cve_data import cve_model_values, merge_cve_records
from .models import CVE


def build_stored_results(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "sslscan": result.get("sslscan_raw", ""),
        "nmap": result.get("nmap_raw", ""),
        "openssl": result.get("openssl_raw", ""),
        "certificate": result.get("certificate"),
        "cipher_suites": result.get("cipher_suites", []),
        "ports": result.get("ports", []),
        "ip_address": result.get("ip_address"),
        "network_metadata": result.get("network_metadata", {}),
        "web_server": result.get("web_server"),
        "risk_decision": result.get("risk_decision", {}),
        "scan_duration_seconds": result.get("scan_duration_seconds"),
        "tool_executions": result.get("tool_executions", {}),
        "scanner_errors": result.get("scanner_errors", {}),
        "protocols": result.get("protocols", []),
        "vulnerabilities": result.get("vulnerabilities", []),
        "nuclei_findings": result.get("nuclei_findings", []),
        "nuclei_raw": result.get("nuclei_raw", ""),
        "nuclei_requested": result.get("nuclei_requested", False),
        "nuclei_success": result.get("nuclei_success", False),
        "nuclei_error": result.get("nuclei_error"),
        "whatweb": result.get("whatweb", {"success": False, "technologies": []}),
        "ssllabs": result.get("ssllabs", {"success": False, "status": "not_run", "grade": "N/A"}),
        "nvd": result.get("nvd", {"success": True, "requested": False, "errors": [], "cves_count": 0}),
        "nvd_cves": result.get("nvd_cves", []),
        "zap_findings": result.get("zap_findings", []),
        "zap_raw": result.get("zap_raw", ""),
        "zap_success": result.get("zap_success", False),
        "zap_error": result.get("zap_error"),
    }


def cve_instances(scan: Any, records: list[dict[str, Any]] | None) -> list[CVE]:
    instances = []
    for record in merge_cve_records(records or []):
        values = cve_model_values(record)
        if values is not None:
            instances.append(CVE(scan=scan, **values))
    return instances


def replace_scan_cves(scan: Any, records: list[dict[str, Any]] | None) -> list[CVE]:
    """Remplace atomiquement la collection liée; l'appelant contrôle la transaction."""
    scan.cves.all().delete()
    instances = cve_instances(scan, records)
    if instances:
        CVE.objects.bulk_create(instances)
    return instances
