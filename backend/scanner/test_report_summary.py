from datetime import datetime, timezone
from types import SimpleNamespace

from django.test import SimpleTestCase

from .report_fixed import _summary_paragraphs, _summary_table_rows


class AnalyticalSummaryParagraphTests(SimpleTestCase):
    def test_requested_text_is_generated_from_scan_data(self):
        scan = SimpleNamespace(
            id=134,
            domaine='google.com',
            date_scan=datetime(2026, 7, 28, 13, 35, tzinfo=timezone.utc),
        )
        metrics = {
            'ports': [{
                'port': 443,
                'protocol': 'tcp',
                'state': 'open',
                'service': 'https',
            }],
        }

        intro, port = _summary_paragraphs(scan, 'Élevé', 8.6, 1.4, metrics)

        self.assertEqual(
            intro,
            'Le rapport présente un audit de sécurité du domaine <b>google.com</b>, réalisé le '
            '<b>28 juillet 2026 à 13:35</b>, sous l\'identifiant de scan <b>134</b>. '
            'Le document classe le niveau de risque comme <b>Élevé</b>, avec un '
            '<b>score IA de 8,6/10</b> et un <b>score de sécurité de 1,4/10</b>.',
        )
        self.assertEqual(
            port,
            'Le seul port ouvert détecté est le <b>port 443</b>, utilisé pour le service '
            '<b>HTTPS</b>. Cette ouverture est normale pour un site web sécurisé.',
        )

    def test_table_rows_use_requested_dynamic_metrics(self):
        metrics = {
            'severity': {'Critique': 0, 'Élevé': 2, 'Moyen': 0, 'Faible': 0},
            'cves': 1,
            'port_count': 1,
            'service_count': 1,
            'technology_count': 12,
            'tls_count': 4,
            'cipher_count': 32,
        }

        rows = _summary_table_rows(metrics, {'expired': False})

        self.assertEqual(rows, [
            ('Vulnérabilités élevées', 2),
            ('Vulnérabilité critique', 0),
            ('CVE officielle', 1),
            ('Port ouvert', 1),
            ('Service détecté', 1),
            ('Technologies', 12),
            ('Versions TLS', 4),
            ('Suites cryptographiques', 32),
            ('Certificat SSL valide', 1),
        ])

    def test_port_text_adapts_to_other_results(self):
        scan = SimpleNamespace(id=9, domaine='example.test', date_scan=None)
        metrics = {'ports': [{'port': 22, 'service': 'ssh'}]}

        intro, port = _summary_paragraphs(scan, 'Moyen', 5.0, 5.0, metrics)

        self.assertIn('<b>example.test</b>', intro)
        self.assertIn('<b>port 22</b>', port)
        self.assertIn('<b>SSH</b>', port)
        self.assertNotIn('normale pour un site web sécurisé', port)
