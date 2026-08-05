from datetime import datetime, timezone
from types import SimpleNamespace

from django.test import SimpleTestCase

from .alert_service import build_alerts


class RelatedValues:
    def __init__(self, values):
        self.values = values

    def all(self):
        return self.values


class AlertDetailsTests(SimpleTestCase):
    def make_scan(self, **overrides):
        defaults = {
            'id': 42,
            'domaine': 'example.test',
            'date_scan': datetime(2026, 7, 30, 10, 0, tzinfo=timezone.utc),
            'score_risque_ia': 7.5,
            'resultats_ssl': {},
            'cves': RelatedValues([]),
            'vulnerabilites_manuelles': RelatedValues([]),
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_cve_alert_contains_popup_details(self):
        cve = SimpleNamespace(
            cve_id='CVE-2026-12345',
            cvss_score=8.1,
            description='Composant vulnérable',
            produit_concerne='nginx 1.24',
            lien_nvd='https://nvd.nist.gov/vuln/detail/CVE-2026-12345',
            recommandation_ia='Mettre nginx à jour.',
        )

        alert = build_alerts([self.make_scan(cves=RelatedValues([cve]))])[0]

        self.assertEqual(alert['source'], 'cve')
        self.assertEqual(alert['details']['source_label'], 'Base NVD / CVE')
        self.assertEqual(alert['details']['identifier'], 'CVE-2026-12345')
        self.assertEqual(alert['details']['recommendation'], 'Mettre nginx à jour.')
        self.assertIn(
            {
                'label': 'Fiche NVD',
                'value': 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345',
                'url': 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345',
            },
            alert['details']['fields'],
        )

    def test_zap_alert_exposes_url_occurrences_and_solution(self):
        scan = self.make_scan(resultats_ssl={
            'zap_findings': [{
                'name': 'Content Security Policy Header Not Set',
                'risk': 'Medium',
                'url': 'https://example.test/login',
                'description': 'En-tête CSP absent.',
                'solution': 'Configurer une politique CSP restrictive.',
                'count': 3,
            }],
        })

        alert = build_alerts([scan])[0]

        self.assertEqual(alert['niveau'], 'MOYEN')
        self.assertEqual(alert['details']['source_label'], 'OWASP ZAP')
        self.assertEqual(
            alert['details']['recommendation'],
            'Configurer une politique CSP restrictive.',
        )
        self.assertIn(
            {
                'label': 'URL concernée',
                'value': 'https://example.test/login',
                'url': 'https://example.test/login',
            },
            alert['details']['fields'],
        )
        self.assertIn(
            {'label': 'Nombre d’occurrences', 'value': '3'},
            alert['details']['fields'],
        )

    def test_safe_scan_still_has_useful_details(self):
        alert = build_alerts([self.make_scan(score_risque_ia=1.2)])[0]

        self.assertEqual(alert['source'], 'scan')
        self.assertEqual(alert['details']['source_label'], 'Analyse globale du scan')
        self.assertIn(
            {'label': 'Score de risque IA', 'value': '1.2/10'},
            alert['details']['fields'],
        )
