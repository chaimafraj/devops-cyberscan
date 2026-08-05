from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from django.core import signing
from django.test import SimpleTestCase, override_settings

from .report_email import (
    REPORT_DOWNLOAD_SALT,
    build_api_report_url,
    build_email_body,
    build_email_context,
    build_email_html,
    build_email_metrics,
    build_email_subject,
    build_logo_png,
    build_qr_png,
    build_report_url,
)


class ReportEmailUrlTests(SimpleTestCase):
    def setUp(self):
        self.scan = SimpleNamespace(id=173)

    @override_settings(
        CYBERSCAN_SITE_URL='https://app.cyberscan.example/',
        CYBERSCAN_HISTORY_URL='https://app.cyberscan.example/historique',
    )
    def test_report_url_targets_the_known_history_page(self):
        self.assertEqual(
            build_report_url(self.scan),
            'https://app.cyberscan.example/historique?scan=173',
        )

    @override_settings(
        CYBERSCAN_HISTORY_URL='https://app.cyberscan.example/historique?vue=rapports',
    )
    def test_report_url_preserves_existing_query_parameters(self):
        self.assertEqual(
            build_report_url(self.scan),
            'https://app.cyberscan.example/historique?vue=rapports&scan=173',
        )

    @override_settings(CYBERSCAN_API_URL='https://api.cyberscan.example/')
    def test_api_url_is_a_signed_email_download_link(self):
        url = build_api_report_url(self.scan)
        parts = urlsplit(url)

        self.assertEqual(
            f'{parts.scheme}://{parts.netloc}{parts.path}',
            'https://api.cyberscan.example/api/scans/173/rapport/email-download/',
        )
        token = parse_qs(parts.query)['token'][0]
        self.assertEqual(
            signing.loads(token, salt=REPORT_DOWNLOAD_SALT),
            {'scan_id': 173},
        )


@override_settings(
    CYBERSCAN_SITE_URL='https://app.cyberscan.example',
    CYBERSCAN_HISTORY_URL='https://app.cyberscan.example/historique',
    CYBERSCAN_API_URL='https://api.cyberscan.example',
)
class ReportEmailContentTests(SimpleTestCase):
    def setUp(self):
        self.scan = SimpleNamespace(
            id=173,
            domaine='audit.example',
            date_scan=datetime(2026, 8, 3, 10, 30, tzinfo=timezone.utc),
            score_risque_ia=7.8,
        )
        self.report_context = {
            'niveau_risque': 'Élevé',
            'score_global_securite': 2.2,
            'cves': [
                {'cvss_score': 9.8, 'severity': 'critical'},
                {'cvss_score': 7.5, 'severity': 'high'},
                {'cvss_score': 5.0, 'severity': 'medium'},
                {'cvss_score': 2.0, 'severity': 'low'},
            ],
            'zap_findings': [],
            'vulnerabilities': ['TLSV1.0'],
            'protocols': [{'status': 'secure'}],
            'ssllabs': {},
            'sslscan': '',
            'openssl': '',
        }

    def test_metrics_are_calculated_from_scan_findings(self):
        metrics = build_email_metrics(self.scan, self.report_context)

        self.assertEqual(metrics['total'], 5)
        self.assertEqual(metrics['critical'], 1)
        self.assertEqual(metrics['high'], 2)
        self.assertEqual(metrics['medium'], 1)
        self.assertEqual(metrics['low'], 1)
        self.assertEqual(metrics['ssl_status'], 'À renforcer')

    def test_context_contains_dynamic_scan_values_and_links(self):
        context = build_email_context(self.scan, self.report_context)

        self.assertEqual(context['domaine'], 'audit.example')
        self.assertEqual(context['date_scan'], '03/08/2026 à 10:30 UTC')
        self.assertEqual(context['niveau_risque'], 'Élevé')
        self.assertEqual(context['score_securite'], '2.2')
        self.assertEqual(context['score_ia'], '7.8')
        self.assertEqual(
            context['url_front'],
            'https://app.cyberscan.example/historique?scan=173',
        )
        self.assertIn(
            'https://api.cyberscan.example/api/scans/173/rapport/email-download/',
            context['url_pdf'],
        )
        self.assertIn('5 vulnérabilité(s)', context['resume_executif'])
        self.assertIn('1 critique(s), 2 élevée(s)', context['resume_executif'])

    def test_html_and_text_versions_include_report_information(self):
        html = build_email_html(self.scan, self.report_context)
        text = build_email_body(self.scan, self.report_context)

        self.assertIn("Rapport d'audit de sécurité disponible", html)
        self.assertIn('cid:cyberscan-logo', html)
        self.assertIn('cid:cyberscan-report-qr', html)
        self.assertIn('Consulter le rapport', html)
        self.assertIn('Télécharger le PDF', html)
        self.assertIn('audit.example', text)
        self.assertIn('Score de sécurité : 2.2/10', text)
        self.assertIn('5 vulnérabilité(s)', text)

    def test_footer_copy_is_present_in_html_and_text_versions(self):
        html = build_email_html(self.scan, self.report_context)
        text = build_email_body(self.scan, self.report_context)
        footer_lines = (
            'Le rapport est également disponible aux formats PDF, Excel et JSON '
            'depuis votre tableau de bord CyberScan.',
            'Nous vous remercions de votre confiance.',
            "L'équipe CyberScan",
            'Cet e-mail a été généré automatiquement par la plateforme CyberScan. '
            'Merci de ne pas répondre à ce message.',
        )

        for line in footer_lines:
            with self.subTest(line=line):
                self.assertIn(line, html)
                self.assertIn(line, text)

    def test_html_uses_email_safe_responsive_layout(self):
        html = build_email_html(self.scan, self.report_context)

        self.assertIn('@media only screen and (max-width: 640px)', html)
        self.assertIn('class="email-shell"', html)
        self.assertIn('class="button-cell"', html)
        self.assertIn('role="presentation"', html)
        self.assertIn('width="640"', html)
        self.assertIn('max-width:640px', html)

    def test_subject_identifies_the_domain(self):
        self.assertEqual(
            build_email_subject(self.scan, self.report_context),
            "[CyberScan] Rapport d'audit de sécurité disponible — audit.example",
        )

    def test_generated_inline_images_are_png_files(self):
        png_signature = b'\x89PNG\r\n\x1a\n'

        self.assertTrue(build_logo_png().startswith(png_signature))
        self.assertTrue(
            build_qr_png('https://app.cyberscan.example/historique?scan=173').startswith(
                png_signature,
            )
        )
