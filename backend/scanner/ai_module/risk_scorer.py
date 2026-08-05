"""Calcul explicable du score de risque CyberScan (0 à 10)."""
import re


class RiskScorer:
    """Agrège les preuves techniques sans créer de risque artificiel."""

    CVSS_WEIGHT = 0.6
    EPSS_WEIGHT = 0.4
    PROD_MULTIPLIER = 1.05
    MONEY_MULTIPLIER = 1.10
    STANDARD_PORTS = {22, 25, 80, 110, 143, 443}
    ZAP_SEVERITY = {
        'critical': 9.0,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.0,
        'informational': 0.0,
        'info': 0.0,
    }
    NUCLEI_SEVERITY = {
        'critical': 9.5,
        'high': 8.0,
        'medium': 5.0,
        'low': 2.0,
        'info': 0.0,
    }
    SSL_LABS_GRADE = {
        'A+': 0.0, 'A': 0.0, 'A-': 0.5,
        'B': 3.0, 'C': 5.0, 'D': 6.5,
        'E': 7.5, 'F': 9.0, 'T': 9.0, 'M': 9.0,
    }

    @staticmethod
    def _bounded_score(value):
        try:
            return max(0.0, min(float(value or 0.0), 10.0))
        except (TypeError, ValueError):
            return 0.0

    def calculate_contextual_score(self, protocols, has_weak_cipher, is_prod=True, has_money=False):
        """Compatibilité avec l'ancien appel, limitée aux preuves SSL/TLS."""
        return self.calculate_scan_score(
            security_signals=protocols,
            has_weak_cipher=has_weak_cipher,
            is_prod=is_prod,
            has_money=has_money,
        )

    def calculate_scan_score(
        self,
        security_signals=None,
        has_weak_cipher=False,
        zap_findings=None,
        nvd_cves=None,
        nmap_raw='',
        ssllabs_result=None,
        nuclei_findings=None,
        is_prod=True,
        has_money=False,
    ):
        """Retourne un score fondé sur la sévérité et le cumul des preuves.

        La preuve la plus grave fixe le niveau de base. La présence de plusieurs
        familles indépendantes ajoute un bonus borné. Le contexte métier ne
        s'applique que si au moins une faiblesse technique a été observée.
        """
        components = []
        signals = {str(item).upper() for item in (security_signals or [])}

        tls_score = 0.0
        if 'TLSV1.0' in signals:
            tls_score = max(tls_score, 7.5)
        if 'TLSV1.1' in signals:
            tls_score = max(tls_score, 6.5)
        if has_weak_cipher or 'WEAK_CIPHER' in signals:
            tls_score = max(tls_score, 7.5)
        if tls_score:
            components.append(tls_score)

        zap_scores = [
            self.ZAP_SEVERITY.get(str(item.get('risk') or '').split()[0].lower(), 0.0)
            for item in (zap_findings or []) if isinstance(item, dict)
        ]
        positive_zap = [score for score in zap_scores if score > 0]
        if positive_zap:
            components.append(min(10.0, max(positive_zap) + min(1.0, 0.15 * (len(positive_zap) - 1))))

        cve_scores = [
            self._bounded_score(item.get('cvss_score'))
            for item in (nvd_cves or []) if isinstance(item, dict)
        ]
        if any(cve_scores):
            components.append(max(cve_scores))

        nuclei_scores = [
            self.NUCLEI_SEVERITY.get(str(item.get('severity') or '').lower(), 0.0)
            for item in (nuclei_findings or []) if isinstance(item, dict)
        ]
        if any(nuclei_scores):
            components.append(max(nuclei_scores))

        open_ports = {
            int(port) for port in re.findall(r'(?mi)^\s*(\d+)/tcp\s+open\b', str(nmap_raw or ''))
        }
        if any(port not in self.STANDARD_PORTS for port in open_ports):
            components.append(5.0)

        grade = str((ssllabs_result or {}).get('grade') or '').upper()
        grade_score = self.SSL_LABS_GRADE.get(grade, 0.0)
        if grade_score:
            components.append(grade_score)

        if not components:
            return 0.0

        score = max(components) + min(1.4, 0.35 * (len(components) - 1))
        if is_prod:
            score *= self.PROD_MULTIPLIER
        if has_money:
            score *= self.MONEY_MULTIPLIER
        return round(min(10.0, score), 1)

    def calculate_cve_risk_score(self, cvss_score, epss_score, is_prod=True, has_money=False):
        """Combine CVSS et EPSS pour le risque d'une CVE individuelle."""
        severity = self._bounded_score(cvss_score) / 10.0
        try:
            exploitability = max(0.0, min(float(epss_score or 0.0), 1.0))
        except (TypeError, ValueError):
            exploitability = 0.0
        base = (self.CVSS_WEIGHT * severity) + (self.EPSS_WEIGHT * exploitability)
        context = 1.0
        if is_prod:
            context *= self.PROD_MULTIPLIER
        if has_money:
            context *= self.MONEY_MULTIPLIER
        return round(min(10.0, base * 10.0 * context), 2)