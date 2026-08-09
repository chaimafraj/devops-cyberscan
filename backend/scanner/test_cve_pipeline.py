from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from .cve_data import collect_scan_cves, normalize_cve_record
from .models import Scan
from .nvd_service import find_cves_for_technologies
from .scan_persistence import build_stored_results, replace_scan_cves


class FakeManager:
    def __init__(self, values):
        self.values = values

    def all(self):
        return self.values


class CveNormalizationTests(SimpleTestCase):
    def test_non_cve_identifier_is_rejected(self):
        self.assertIsNone(normalize_cve_record({"cve_id": "NUCLEI-HEADER-001"}))

    def test_database_and_nvd_fields_are_merged_without_losing_values(self):
        database_cve = SimpleNamespace(
            cve_id="CVE-2026-12345",
            cvss_score=8.1,
            description="Description enregistrée",
            recommandation_ia="Mettre à jour",
            produit_concerne="",
            lien_nvd="",
        )
        scan = SimpleNamespace(cves=FakeManager([database_cve]))
        results = {
            "nvd_cves": [{
                "cve_id": "CVE-2026-12345",
                "cvss_score": 8.1,
                "description": "Description NVD",
                "produit_concerne": "nginx 1.20.0",
                "lien_nvd": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
            }],
        }

        records = collect_scan_cves(scan, results)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["description"], "Description enregistrée")
        self.assertEqual(records[0]["produit_concerne"], "nginx 1.20.0")
        self.assertEqual(
            records[0]["lien_nvd"],
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        )

    def test_legacy_tls10_poodle_mapping_is_filtered_without_sslv3_proof(self):
        database_cve = SimpleNamespace(
            cve_id="CVE-2014-3566",
            cvss_score=7.5,
            description="Protocole TLSv1.0 obsolète détecté, vulnérable aux attaques POODLE.",
            recommandation_ia="Désactiver TLS 1.0.",
            produit_concerne="",
            lien_nvd="",
        )
        scan = SimpleNamespace(cves=FakeManager([database_cve]))

        records = collect_scan_cves(
            scan,
            {"sslscan": "SSLv3 disabled\nTLSv1.0 enabled"},
        )

        self.assertEqual(records, [])

    def test_legacy_sweet32_product_comes_from_recorded_3des_evidence(self):
        database_cve = SimpleNamespace(
            cve_id="CVE-2016-2183",
            cvss_score=7.5,
            description="Suites de chiffrement 3DES détectées.",
            recommandation_ia="Désactiver Triple-DES.",
            produit_concerne="",
            lien_nvd="",
        )
        scan = SimpleNamespace(cves=FakeManager([database_cve]))

        records = collect_scan_cves(
            scan,
            {"sslscan": "Accepted TLSv1.2 112 bits TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
        )

        self.assertEqual(records[0]["produit_concerne"], "Suites TLS Triple-DES acceptées")
    @patch("scanner.nvd_service._query_nvd_cpe")
    def test_nvd_enrichment_contains_all_five_required_fields(self, query):
        query.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-12345",
                    "published": "2026-01-02T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "nginx 1.20.0 issue."}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"},
                        }],
                    },
                },
            }],
        }

        result = find_cves_for_technologies([
            {"name": "nginx", "version": ["1.20.0"]},
        ])

        self.assertTrue(result["success"])
        self.assertEqual(len(result["cves"]), 1)
        cve = result["cves"][0]
        self.assertEqual(cve["cve_id"], "CVE-2026-12345")
        self.assertEqual(cve["cvss_score"], 8.1)
        self.assertEqual(cve["description"], "nginx 1.20.0 issue.")
        self.assertEqual(cve["produit_concerne"], "nginx 1.20.0")
        self.assertEqual(
            cve["lien_nvd"],
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        )


class CvePersistenceTests(TestCase):
    def test_persistence_keeps_only_real_cve_ids_and_all_metadata(self):
        scan = Scan.objects.create(domaine="audit.example")

        replace_scan_cves(scan, [
            {
                "cve_id": "NUCLEI-HEADER-001",
                "cvss_score": 9,
                "description": "Template générique",
            },
            {
                "cve_id": "CVE-2026-12345",
                "cvss_score": 8.1,
                "description": "Description exacte",
                "produit_concerne": "nginx 1.20.0",
                "lien_nvd": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
                "recommandation_ia": "Mettre à jour nginx.",
            },
        ])

        cve = scan.cves.get()
        self.assertEqual(cve.cve_id, "CVE-2026-12345")
        self.assertEqual(cve.cvss_score, 8.1)
        self.assertEqual(cve.description, "Description exacte")
        self.assertEqual(cve.produit_concerne, "nginx 1.20.0")
        self.assertEqual(
            cve.lien_nvd,
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        )

    def test_stored_results_preserve_scanner_outputs(self):
        result = {
            "sslscan_raw": "ssl",
            "nmap_raw": "nmap",
            "openssl_raw": "openssl",
            "certificate": {"subject": "CN=audit.example"},
            "cipher_suites": [{"name": "TLS_AES_256_GCM_SHA384"}],
            "ports": [{"port": 443}],
            "ip_address": "192.0.2.10",
            "network_metadata": {"asn": "AS64500"},
            "web_server": "nginx",
            "scan_duration_seconds": 12.5,
            "protocols": [{"name": "TLSv1.3"}],
            "vulnerabilities": [],
            "nvd_cves": [{"cve_id": "CVE-2026-12345"}],
        }

        stored = build_stored_results(result)

        for key in (
            "sslscan", "nmap", "openssl", "certificate", "cipher_suites",
            "ports", "ip_address", "network_metadata", "web_server",
            "scan_duration_seconds", "scanner_errors", "protocols",
            "vulnerabilities", "nvd_cves",
        ):
            self.assertIn(key, stored)


class ScannerCveEvidenceTests(SimpleTestCase):
    def scanner_patches(self, sslscan_raw):
        return (
            patch("scanner.views.run_sslscan", return_value={"success": True, "raw": sslscan_raw}),
            patch("scanner.views.run_nmap", return_value={"success": True, "raw": "443/tcp open https"}),
            patch("scanner.views.run_openssl", return_value={"success": True, "raw": ""}),
            patch("scanner.views.run_whatweb", return_value={"success": True, "technologies": []}),
            patch("scanner.views.run_ssllabs", return_value={"success": True, "grade": "A"}),
        )

    def run_scan(self, sslscan_raw):
        patches = self.scanner_patches(sslscan_raw)
        started = [item.start() for item in patches]
        try:
            from .views import scan_single_site
            return scan_single_site(
                "audit.example",
                is_prod=False,
                options={"zap": False, "nvd": False, "network_metadata": False},
            )
        finally:
            for item in reversed(patches):
                item.stop()

    def test_scan_records_real_execution_metadata_for_each_tool(self):
        result = self.run_scan("TLSv1.2 enabled")

        self.assertEqual(
            set(result["tool_executions"]),
            {"sslscan", "nmap", "openssl", "whatweb", "ssllabs"},
        )
        for execution in result["tool_executions"].values():
            self.assertIn("started_at", execution)
            self.assertIn("completed_at", execution)
            self.assertGreaterEqual(execution["duration_seconds"], 0)
            self.assertTrue(execution["success"])

    @patch(
        "scanner.views.run_nuclei",
        return_value={
            "success": True,
            "raw": '{"template-id":"header-check"}',
            "findings": [{
                "template_id": "header-check",
                "name": "Missing security header",
                "severity": "medium",
                "description": "Header missing",
                "matched_at": "https://audit.example",
            }],
        },
    )
    def test_nuclei_option_runs_the_website_scanner(self, run_nuclei):
        patches = self.scanner_patches("TLSv1.2 enabled")
        started = [item.start() for item in patches]
        try:
            from .views import scan_single_site
            result = scan_single_site(
                "audit.example:8443",
                is_prod=False,
                options={
                    "nuclei": True,
                    "zap": False,
                    "nvd": False,
                    "network_metadata": False,
                },
            )
        finally:
            for item in reversed(patches):
                item.stop()

        run_nuclei.assert_called_once()
        self.assertEqual(run_nuclei.call_args.args, ("audit.example", 8443))
        self.assertIn("cancel_check", run_nuclei.call_args.kwargs)
        self.assertTrue(result["nuclei_success"])
        self.assertTrue(result["nuclei_requested"])
        self.assertEqual(result["nuclei_findings"][0]["template_id"], "header-check")
        self.assertIn("nuclei", result["tool_executions"])

    def test_sslscan_timeout_keeps_partial_scan_when_nmap_succeeds(self):
        patches = (
            patch(
                "scanner.views.run_sslscan",
                return_value={"success": False, "error": "sslscan timeout", "raw": ""},
            ),
            patch(
                "scanner.views.run_nmap",
                return_value={"success": True, "error": None, "raw": "443/tcp open https"},
            ),
            patch(
                "scanner.views.run_openssl",
                return_value={"success": False, "error": "openssl failed", "raw": ""},
            ),
            patch(
                "scanner.views.run_whatweb",
                return_value={"success": False, "error": "whatweb failed", "technologies": []},
            ),
            patch(
                "scanner.views.run_ssllabs",
                return_value={"success": False, "error": "ssllabs failed", "grade": "N/A"},
            ),
        )
        started = [item.start() for item in patches]
        try:
            from .views import scan_single_site
            result = scan_single_site(
                "audit.example",
                is_prod=False,
                options={"zap": False, "nvd": False, "network_metadata": False},
            )
        finally:
            for item in reversed(patches):
                item.stop()

        self.assertTrue(result["success"])
        self.assertEqual(result["scanner_errors"]["sslscan"], "sslscan timeout")
        self.assertFalse(result["tool_executions"]["sslscan"]["success"])
        self.assertTrue(result["tool_executions"]["nmap"]["success"])
    def test_tls_10_signal_is_not_mislabeled_as_poodle_cve(self):
        result = self.run_scan("TLSv1.0 enabled\nTLSv1.2 enabled")

        self.assertIn("TLSv1.0", result["vulnerabilities"])
        self.assertEqual(result["cves"], [])

    @patch("scanner.views._get_recommender")
    def test_accepted_3des_has_complete_sweet32_cve(self, recommender):
        recommender.return_value.generate_remediation.return_value = "Désactiver Triple-DES."

        result = self.run_scan(
            "TLSv1.2 enabled\nAccepted TLSv1.2 112 bits ECDHE-RSA-DES-CBC3-SHA"
        )

        self.assertEqual(len(result["cves"]), 1)
        cve = result["cves"][0]
        self.assertEqual(cve["cve_id"], "CVE-2016-2183")
        self.assertEqual(cve["cvss_score"], 7.5)
        self.assertTrue(cve["description"])
        self.assertEqual(cve["produit_concerne"], "Suites TLS Triple-DES acceptées")
        self.assertEqual(
            cve["lien_nvd"],
            "https://nvd.nist.gov/vuln/detail/CVE-2016-2183",
        )
