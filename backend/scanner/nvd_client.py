"""Compatibilité : le client NVD historique délègue au service validé unique."""

from .nvd_service import (
    NVD_CVE_API_URL,
    NVD_PUBLIC_REQUEST_LIMIT,
    NVD_RESULTS_PER_TECHNOLOGY,
    find_cves_for_technologies,
)

__all__ = [
    "NVD_CVE_API_URL",
    "NVD_PUBLIC_REQUEST_LIMIT",
    "NVD_RESULTS_PER_TECHNOLOGY",
    "find_cves_for_technologies",
]