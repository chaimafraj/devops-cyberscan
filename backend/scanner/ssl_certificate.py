"""Extraction normalisee des informations de certificat depuis les outils SSL."""
import re
from datetime import datetime, timezone

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
DATE_FORMAT = "%b %d %H:%M:%S %Y GMT"

def _match(pattern, text):
    found = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return found.group(1).strip() if found else None

def _date(value):
    if not value:
        return None
    try:
        return datetime.strptime(re.sub(r"\s+", " ", value), DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None

def extract_certificate(sslscan_raw="", openssl_raw="", now=None):
    sslscan = ANSI_RE.sub("", sslscan_raw or "")
    openssl = ANSI_RE.sub("", openssl_raw or "")
    combined = f"{sslscan}\n{openssl}"
    subject = (_match(r"^Subject:\s*(.+)$", sslscan) or
               _match(r"^subject\s*=\s*(.+)$", openssl) or
               _match(r"^\s*0\s+s:(.+)$", openssl))
    if not (subject or "-----BEGIN CERTIFICATE-----" in combined or
            re.search(r"(?im)^\s*SSL Certificate:\s*$", sslscan)):
        return None
    before_raw = (_match(r"^Not valid before:\s*(.+)$", sslscan) or
                  _match(r"\bv:NotBefore:\s*(.+?)(?:;\s*NotAfter:|$)", openssl))
    after_raw = (_match(r"^Not valid after:\s*(.+)$", sslscan) or
                 _match(r"\bNotAfter:\s*(.+)$", openssl))
    before, after = _date(before_raw), _date(after_raw)
    expired = after < (now or datetime.now(timezone.utc)) if after else None
    alts = _match(r"^Altnames:\s*(.+)$", sslscan) or ""
    return {
        "available": True, "subject": subject,
        "issuer": (_match(r"^Issuer:\s*(.+)$", sslscan) or _match(r"^issuer\s*=\s*(.+)$", openssl)),
        "alt_names": [x.strip().removeprefix("DNS:") for x in alts.split(",") if x.strip()],
        "not_before": before.isoformat() if before else None,
        "not_after": after.isoformat() if after else None,
        "expired": expired,
        "status": "expired" if expired else "valid" if expired is False else "available",
        "signature_algorithm": _match(r"^Signature Algorithm:\s*(.+)$", sslscan),
        "key_strength": _match(r"^(?:RSA )?Key Strength:\s*(.+)$", sslscan),
    }
