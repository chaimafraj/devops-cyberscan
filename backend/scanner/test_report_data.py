from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

from .report_data import (
    build_report_metrics, collect_cves, extract_duration_seconds, fetch_network_metadata,
    normalize_results, tool_names_with_results,
)
from .report_fixed import _activated_tools, _build_findings
from .report_graphics import _bars, _pie
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import String
from .report_generator import risk_level_from_score


SSL_SCAN = """
SSL/TLS Protocols:
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled
Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384
Accepted  TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384
SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength: 4096
Subject: *.tlfnet.com.tn
Altnames: DNS:*.tlfnet.com.tn, DNS:tlfnet.com.tn
Issuer: RapidSSL G5 TLS RSA4096 SHA384 2022 CA1
Not valid before: Mar 16 00:00:00 2026 GMT
Not valid after: Sep 30 23:59:59 2026 GMT
"""
NMAP = """Nmap scan report for www.tlfnet.com.tn (102.217.210.147)
Host is up.
PORT    STATE SERVICE VERSION
80/tcp  open  http    nginx
443/tcp open  https   nginx
Nmap done: 1 IP address (1 host up) scanned in 17.54 seconds
"""
WHATWEB = {"success": True, "technologies": [
    {"name": "IP", "string": ["102.217.210.147"], "version": []},
    {"name": "HTTPServer", "string": ["nginx/1.24"], "version": []},
    {"name": "HTML5", "string": [], "version": []},
]}


class FakeCveManager:
    def __init__(self, values):
        self.values = values

    def all(self):
        return self.values


class ReportDataTests(SimpleTestCase):
    def setUp(self):
        self.results = {
            "sslscan": SSL_SCAN, "openssl": "subject=CN=*.tlfnet.com.tn",
            "nmap": NMAP, "whatweb": WHATWEB,
            "network_metadata": {"ip_address": "102.217.210.147", "asn": 2609, "hoster": "Tunisie Telecom"},
            "nvd": {"success": True, "cves_count": 1},
            "nvd_cves": [{"cve_id": "CVE-2026-0001", "cvss_score": 7.5, "description": "Test CVE"}],
            "vulnerabilities": [], "scan_duration_seconds": 42.4,
        }

    def test_normalization_recovers_all_real_scan_fields(self):
        data = normalize_results(self.results)
        self.assertEqual(data["ip_address"], "102.217.210.147")
        self.assertEqual(data["web_server"], "nginx/1.24")
        self.assertEqual(data["hoster"], "Tunisie Telecom")
        self.assertEqual(data["asn"], "AS2609")
        self.assertEqual([(p["port"], p["service"]) for p in data["ports"]], [(80, "http"), (443, "https")])
        self.assertEqual([p["name"] for p in data["protocols"]], ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"])
        self.assertEqual(len(data["cipher_suites"]), 3)
        self.assertEqual(data["certificate"]["issuer"], "RapidSSL G5 TLS RSA4096 SHA384 2022 CA1")
        self.assertEqual(data["certificate"]["not_after"], "2026-09-30T23:59:59+00:00")

    def test_tools_count_only_tools_with_results(self):
        expected = ["SSLScan", "Nmap", "OpenSSL", "WhatWeb", "NVD"]
        self.assertEqual(tool_names_with_results(self.results), expected)
        self.assertEqual(_activated_tools(self.results), expected)

    def test_duration_prefers_measured_total(self):
        scan = SimpleNamespace(
            started_at=datetime.now(timezone.utc) - timedelta(seconds=100),
            completed_at=datetime.now(timezone.utc),
        )
        self.assertEqual(extract_duration_seconds(scan, self.results), 42.4)

    def test_cve_count_and_vulnerability_sheets_share_sources(self):
        model_cve = SimpleNamespace(
            cve_id="CVE-2026-0001", cvss_score=7.5, description="Test CVE",
            recommandation_ia="Mettre à jour",
        )
        scan = SimpleNamespace(domaine="www.tlfnet.com.tn", cves=FakeCveManager([model_cve]))
        cves = collect_cves(scan, self.results)
        findings = _build_findings(scan, normalize_results(self.results))
        self.assertEqual(len(cves), 1)
        self.assertEqual(sum(item["source_id"] == "CVE-2026-0001" for item in findings), 1)
        self.assertEqual(len(findings), 1)

    def test_nuclei_finding_is_included_with_its_evidence_and_remediation(self):
        scan = SimpleNamespace(domaine="audit.example", cves=FakeCveManager([]))
        results = dict(self.results)
        results["nvd_cves"] = []
        results["nuclei_findings"] = [{
            "template_id": "http-misconfiguration",
            "name": "Exposed administration panel",
            "severity": "high",
            "description": "An administration panel is publicly reachable.",
            "matched_at": "https://audit.example/admin",
            "remediation": "Restrict access to trusted networks.",
        }]

        findings = _build_findings(scan, normalize_results(results))
        nucleus = next(item for item in findings if item["type"] == "Nuclei")

        self.assertEqual(nucleus["source_id"], "http-misconfiguration")
        self.assertIn("https://audit.example/admin", nucleus["evidence"])
        self.assertEqual(nucleus["description"], "An administration panel is publicly reachable.")
        self.assertEqual(nucleus["recommendation"], "Restrict access to trusted networks.")

    def test_risk_levels_use_one_consistent_scale(self):
        self.assertEqual(risk_level_from_score(3.9)[0], "Faible")
        self.assertEqual(risk_level_from_score(4)[0], "Moyen")
        self.assertEqual(risk_level_from_score(7)[0], "Élevé")
        self.assertEqual(risk_level_from_score(9)[0], "Critique")

    @override_settings(IP_METADATA_LOOKUP_ENABLED=True, IP_METADATA_URL="https://example.test/{ip}", IP_METADATA_TIMEOUT=3)
    @patch("scanner.report_data.requests.get")
    def test_network_metadata_is_stored_from_real_response(self, get):
        response = Mock()
        response.json.return_value = {"success": True, "connection": {"asn": 2609, "org": "Tunisie Telecom", "isp": "TT"}}
        response.raise_for_status.return_value = None
        get.return_value = response
        self.assertEqual(fetch_network_metadata("102.217.210.147")["asn"], 2609)
        get.assert_called_once_with("https://example.test/102.217.210.147", timeout=3)
    def test_all_report_counters_are_exact(self):
        second_cve = SimpleNamespace(
            cve_id="CVE-2026-0002", cvss_score=5.0, description="Second CVE",
            recommandation_ia="Corriger",
        )
        first_cve = SimpleNamespace(
            cve_id="CVE-2026-0001", cvss_score=7.5, description="Test CVE",
            recommandation_ia="Mettre à jour",
        )
        scan = SimpleNamespace(
            cves=FakeCveManager([first_cve, second_cve]),
            started_at=None, completed_at=None,
        )
        results = dict(self.results)
        results["nvd_cves"] = []
        results["nmap"] = NMAP.replace(
            "443/tcp open  https   nginx",
            "443/tcp open  https   nginx\n8443/tcp open  https-alt nginx",
        )
        findings = [
            {"severity": "Critique"}, {"severity": "Élevé"},
            {"severity": "Élevé"}, {"severity": "Moyen"}, {"severity": "Faible"},
        ]
        metrics = build_report_metrics(scan, normalize_results(results), findings)
        self.assertEqual(metrics["severity"], {
            "Critique": 1, "Élevé": 2, "Moyen": 1, "Faible": 1,
        })
        self.assertEqual(metrics["cves"], 2)
        self.assertEqual(metrics["port_count"], 3)
        self.assertEqual(metrics["service_count"], 3)
        self.assertEqual(metrics["technology_count"], 3)
        self.assertEqual(metrics["tool_count"], 4)

    def test_severity_graph_uses_the_same_exact_counts(self):
        scan = SimpleNamespace(cves=FakeCveManager([]), started_at=None, completed_at=None)
        findings = [
            {"severity": "Critique"}, {"severity": "Élevé"},
            {"severity": "Élevé"}, {"severity": "Moyen"}, {"severity": "Faible"},
        ]
        metrics = build_report_metrics(scan, normalize_results(self.results), findings)
        drawing = _pie(findings, metrics)
        chart = next(item for item in drawing.contents if isinstance(item, Pie))
        self.assertEqual(chart.data, [1, 2, 1, 1])
        self.assertEqual(chart.labels, ["Critique (1)", "Élevé (2)", "Moyen (1)", "Faible (1)"])

    def test_network_graph_labels_come_from_real_ports(self):
        entries = [("80/tcp http", 1), ("443/tcp https", 1)]
        drawing = _bars("Ports ouverts", entries)
        labels = [item.text for item in drawing.contents if isinstance(item, String)]
        self.assertIn("80/tcp http", labels)
        self.assertIn("443/tcp https", labels)
