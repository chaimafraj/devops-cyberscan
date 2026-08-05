from datetime import datetime, timezone
from django.test import SimpleTestCase
from .report_graphics import _certificate_metrics
from .ssl_certificate import extract_certificate

class CertificateExtractionTests(SimpleTestCase):
    RAW = """SSL Certificate:\nSignature Algorithm: sha256WithRSAEncryption\nRSA Key Strength: 4096\nSubject: *.tlfnet.com.tn\nAltnames: DNS:*.tlfnet.com.tn, DNS:tlfnet.com.tn\nIssuer: RapidSSL G5 TLS RSA4096 SHA384 2022 CA1\nNot valid before: Mar 16 00:00:00 2026 GMT\nNot valid after: Sep 30 23:59:59 2026 GMT\n"""

    def test_extracts_valid_certificate(self):
        cert = extract_certificate(self.RAW, now=datetime(2026, 7, 28, tzinfo=timezone.utc))
        self.assertTrue(cert["available"])
        self.assertEqual(cert["status"], "valid")
        self.assertFalse(cert["expired"])
        self.assertEqual(cert["subject"], "*.tlfnet.com.tn")

    def test_report_recovers_historical_raw_certificate(self):
        self.assertEqual(_certificate_metrics({"sslscan": self.RAW}), (1, 0))

    def test_absent_certificate_stays_unavailable(self):
        self.assertIsNone(extract_certificate("TLSv1.3 enabled", "CONNECTED"))
        self.assertEqual(_certificate_metrics({"sslscan": "TLSv1.3 enabled"}), (None, None))
