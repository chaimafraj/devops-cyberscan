"""Normalisation des donnees techniques utilisees par les rapports CyberScan."""
from __future__ import annotations

import ipaddress
import re
from copy import deepcopy

import requests
from django.conf import settings

from .cve_data import collect_scan_cves
from .ssl_certificate import extract_certificate

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def clean_raw(value):
    return ANSI_RE.sub("", str(value or "")).replace("\r", "")


def _first_mapping_value(mapping, keys):
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}):
            if isinstance(value, dict):
                value = value.get("name") or value.get("number") or value.get("value")
            if value not in (None, ""):
                return value
    return None


def technologies(results):
    value = (results.get("whatweb") or {}).get("technologies") or results.get("technologies") or []
    return [item for item in value if isinstance(item, dict) and item.get("name")]


def _technology_values(results, *names):
    wanted = {name.lower() for name in names}
    values = []
    for item in technologies(results):
        if str(item.get("name", "")).lower() not in wanted:
            continue
        for field in ("string", "version"):
            raw = item.get(field) or []
            if not isinstance(raw, list):
                raw = [raw]
            values.extend(str(value).strip() for value in raw if str(value).strip())
    return list(dict.fromkeys(values))


def extract_ports(results):
    explicit = results.get("ports") or results.get("open_ports")
    if isinstance(explicit, list):
        normalized = []
        for item in explicit:
            if isinstance(item, dict) and item.get("port") is not None:
                normalized.append({
                    "port": int(item["port"]), "protocol": item.get("protocol", "tcp"),
                    "state": item.get("state", "open"), "service": item.get("service") or "unknown",
                    "details": item.get("details", ""),
                })
        if normalized:
            return normalized
    ports = []
    pattern = re.compile(r"(?mi)^\s*(\d+)/(tcp|udp)\s+(open\w*)\s+([^\s]+)(?:\s+(.*))?$")
    for port, protocol, state, service, details in pattern.findall(clean_raw(results.get("nmap"))):
        ports.append({"port": int(port), "protocol": protocol, "state": state,
                      "service": service, "details": details.strip()})
    return ports


def extract_ip_address(results):
    direct = _first_mapping_value(results, ("ip_address", "resolved_ip", "ip"))
    candidates = [direct]
    for key in ("network", "network_metadata", "ip_info", "ipinfo", "rdap", "asset"):
        candidates.append(_first_mapping_value(results.get(key), ("ip_address", "resolved_ip", "ip", "query")))
    candidates.extend(_technology_values(results, "IP"))
    nmap = clean_raw(results.get("nmap"))
    match = re.search(r"(?mi)^Nmap scan report for .+?\s+\(([0-9a-f:.]+)\)\s*$", nmap)
    if match:
        candidates.append(match.group(1))
    match = re.search(r"(?mi)^Nmap scan report for\s+([0-9a-f:.]+)\s*$", nmap)
    if match:
        candidates.append(match.group(1))
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(str(candidate).strip()))
        except ValueError:
            continue
    return None


def extract_web_server(results):
    direct = _first_mapping_value(results, ("web_server", "server", "http_server"))
    if direct:
        return str(direct)
    values = _technology_values(results, "HTTPServer", "WebServer")
    return ", ".join(values) if values else None


def extract_network_identity(results):
    mappings = [results]
    mappings.extend(results.get(key) for key in ("network", "network_metadata", "ip_info", "ipinfo", "rdap"))
    asn = hoster = None
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        connection = mapping.get("connection") or {}
        data = mapping.get("data") or {}
        if isinstance(data, dict) and isinstance(data.get("connection"), dict):
            connection = data["connection"]
        asn = asn or _first_mapping_value(mapping, ("asn", "asn_number", "autonomous_system_number"))
        asn = asn or _first_mapping_value(connection, ("asn", "asn_number", "number"))
        hoster = hoster or _first_mapping_value(mapping, ("hoster", "hosting_provider", "provider", "isp", "organization", "org"))
        hoster = hoster or _first_mapping_value(connection, ("asn_org", "org", "isp", "organization"))
    if asn is not None:
        asn = str(asn).upper()
        if asn.isdigit():
            asn = f"AS{asn}"
    return hoster, asn


def extract_tls_versions(results):
    merged = {}
    for item in results.get("protocols") or []:
        if isinstance(item, dict) and item.get("name"):
            merged[str(item["name"])] = {"name": str(item["name"]), "status": str(item.get("status") or "unknown").lower()}
    for name, status in re.findall(r"(?mi)^\s*(TLSv1\.[0-3])\s+(enabled|disabled)\s*$", clean_raw(results.get("sslscan"))):
        secure = "secure" if status.lower() == "enabled" and name in ("TLSv1.2", "TLSv1.3") else status.lower()
        merged[name] = {"name": name, "status": secure}
    order = {name: index for index, name in enumerate(("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"))}
    return sorted(merged.values(), key=lambda item: order.get(item["name"], 99))


def extract_cipher_suites(results):
    explicit = results.get("cipher_suites") or results.get("ciphers")
    if isinstance(explicit, list) and explicit:
        return explicit
    suites = []
    seen = set()
    pattern = re.compile(r"(?mi)^\s*(Preferred|Accepted)\s+(TLSv1\.[0-3])\s+(\d+)\s+bits\s+([A-Z0-9_-]+)")
    for preference, protocol, bits, name in pattern.findall(clean_raw(results.get("sslscan"))):
        key = (protocol, name)
        if key in seen:
            continue
        seen.add(key)
        suites.append({"name": name, "protocol": protocol, "bits": int(bits),
                       "preference": preference.lower()})
    return suites


def extract_duration_seconds(scan, results):
    for key in ("scan_duration_seconds", "duration_seconds", "total_duration_seconds"):
        try:
            if results.get(key) is not None:
                return max(0.0, float(results[key]))
        except (TypeError, ValueError):
            pass
    started = getattr(scan, "started_at", None)
    completed = getattr(scan, "completed_at", None)
    if started and completed:
        return max(0.0, (completed - started).total_seconds())
    timings = results.get("tool_timings") or results.get("timings")
    if isinstance(timings, dict) and timings:
        try:
            return sum(max(0.0, float(value)) for value in timings.values())
        except (TypeError, ValueError):
            pass
    return None


def tool_names_with_results(results):
    whatweb = results.get("whatweb") or {}
    ssllabs = results.get("ssllabs") or results.get("ssl_labs") or {}
    nvd = results.get("nvd") or {}
    checks = [
        ("SSLScan", bool(clean_raw(results.get("sslscan")))),
        ("Nmap", bool(clean_raw(results.get("nmap")))),
        ("OpenSSL", bool(clean_raw(results.get("openssl")))),
        ("WhatWeb", bool(whatweb.get("technologies") or whatweb.get("success") is True)),
        ("Nuclei", bool(results.get("nuclei_findings") or results.get("nuclei_raw") or results.get("nuclei_success") is True)),
        ("OWASP ZAP", bool(results.get("zap_findings") or results.get("zap_raw") or results.get("zap_success") is True)),
        ("SSL Labs", bool(ssllabs.get("success") is True or (ssllabs.get("grade") not in (None, "", "N/A")))),
        ("NVD", bool(results.get("nvd_cves") or (nvd.get("requested") is True and nvd.get("success") is True))),
    ]
    return [name for name, available in checks if available]


def tool_execution_issues(results):
    """Retourne uniquement les échecs réels des outils activés."""
    issues = []

    def add(tool, detail):
        cleaned = str(detail or "").strip()
        if cleaned:
            issues.append({"tool": tool, "detail": cleaned[:300]})

    whatweb = results.get("whatweb") or {}
    if whatweb.get("success") is False and whatweb.get("error"):
        add("WhatWeb", whatweb["error"])

    ssllabs = results.get("ssllabs") or results.get("ssl_labs") or {}
    if ssllabs.get("success") is False and ssllabs.get("status") not in (None, "", "not_run"):
        add("SSL Labs", ssllabs.get("error") or f"statut {ssllabs.get('status')}")

    zap_error = results.get("zap_error")
    if results.get("zap_success") is False and zap_error and "désactiv" not in str(zap_error).casefold():
        add("OWASP ZAP", zap_error)

    nuclei_error = results.get("nuclei_error")
    if (
        results.get("nuclei_success") is False
        and nuclei_error
        and "disabled" not in str(nuclei_error).casefold()
        and "désactiv" not in str(nuclei_error).casefold()
    ):
        add("Nuclei", nuclei_error)

    nvd = results.get("nvd") or {}
    if nvd.get("requested") is True and nvd.get("success") is False:
        add("NVD", "; ".join(str(item) for item in nvd.get("errors") or []) or "requête en échec")

    return issues

def collect_cves(scan, results):
    return collect_scan_cves(scan, results)

def build_report_metrics(scan, results, findings):
    """Source unique pour les KPI, tableaux statistiques et graphiques."""
    ports = extract_ports(results)
    severity = {
        label: sum(1 for item in findings if item.get("severity") == label)
        for label in ("Critique", "Élevé", "Moyen", "Faible")
    }
    service_counts = {}
    for port in ports:
        service = port.get("service") or "unknown"
        service_counts[service] = service_counts.get(service, 0) + 1
    technology_items = technologies(results)
    tools = tool_names_with_results(results)
    cves = collect_cves(scan, results)
    return {
        "severity": severity,
        "findings": len(findings),
        "cves": len(cves),
        "cve_records": cves,
        "ports": ports,
        "port_count": len(ports),
        "service_counts": service_counts,
        "service_count": len(service_counts),
        "technologies": technology_items,
        "technology_count": len(technology_items),
        "tools": tools,
        "tool_count": len(tools),
        "tls_count": len(extract_tls_versions(results)),
        "cipher_count": len(extract_cipher_suites(results)),
        "duration_seconds": extract_duration_seconds(scan, results),
    }

def normalize_results(results):
    normalized = deepcopy(results) if isinstance(results, dict) else {}
    normalized["ports"] = extract_ports(normalized)
    normalized["protocols"] = extract_tls_versions(normalized)
    normalized["cipher_suites"] = extract_cipher_suites(normalized)
    normalized["certificate"] = (normalized.get("certificate") or
        extract_certificate(normalized.get("sslscan", ""), normalized.get("openssl", "")))
    normalized["ip_address"] = extract_ip_address(normalized)
    normalized["web_server"] = extract_web_server(normalized)
    hoster, asn = extract_network_identity(normalized)
    normalized["hoster"], normalized["asn"] = hoster, asn
    return normalized


def fetch_network_metadata(ip_address, timeout=None):
    """Enrichissement optionnel; aucune valeur n'est inventée en cas d'échec."""
    if not ip_address:
        return {}
    if not getattr(settings, "IP_METADATA_LOOKUP_ENABLED", True):
        return {"ip_address": ip_address}
    timeout = timeout or getattr(settings, "IP_METADATA_TIMEOUT", 8)
    url = getattr(settings, "IP_METADATA_URL", "https://ipwho.is/{ip}").format(ip=ip_address)
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
        if payload.get("success") is False:
            return {"ip_address": ip_address}
        connection = payload.get("connection") or {}
        return {"ip_address": ip_address, "asn": connection.get("asn"),
                "hoster": connection.get("org") or connection.get("isp"),
                "isp": connection.get("isp"), "source": "ipwho.is"}
    except (requests.RequestException, ValueError, TypeError):
        return {"ip_address": ip_address}