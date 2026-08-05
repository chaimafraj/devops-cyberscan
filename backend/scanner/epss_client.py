"""Small client for the FIRST.org EPSS API.

EPSS (Exploit Prediction Scoring System) gives, for a CVE, the probability
[0, 1] that it will be exploited in the wild within the next 30 days. It
complements CVSS: CVSS says how severe a flaw is, EPSS says how likely it is
to actually be attacked.

API docs: https://www.first.org/epss/api
"""

import requests


EPSS_API_URL = 'https://api.first.org/data/v1/epss'
# The API accepts a comma-separated list of CVE ids; keep chunks small enough
# to stay well under URL length limits on large scans.
EPSS_BATCH_SIZE = 100


def get_epss_scores(cve_ids):
    """Return ``{cve_id: epss_probability}`` for the given CVE ids.

    ``epss_probability`` is a float in [0, 1]. CVEs unknown to EPSS (too new,
    rejected, or not an application CVE) are simply omitted from the result, so
    callers should default a missing score to ``0.0``.
    """
    scores = {}
    # De-duplicate while preserving order and dropping empty ids.
    unique_ids = [cve_id for cve_id in dict.fromkeys(cve_ids) if cve_id]

    for start in range(0, len(unique_ids), EPSS_BATCH_SIZE):
        chunk = unique_ids[start:start + EPSS_BATCH_SIZE]
        try:
            response = requests.get(
                EPSS_API_URL,
                params={'cve': ','.join(chunk)},
                timeout=20,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError):
            # A failed batch just means those CVEs get no EPSS score; the risk
            # score will fall back to CVSS-only. Do not abort the whole scan.
            continue

        for item in payload.get('data', []):
            cve_id = item.get('cve')
            if not cve_id:
                continue
            try:
                scores[cve_id] = float(item.get('epss', 0.0))
            except (TypeError, ValueError):
                continue

    return scores
