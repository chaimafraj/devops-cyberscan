from __future__ import annotations

import time

from .models import Scan


class ScanCancelled(Exception):
    """Interruption volontaire demandée par le propriétaire du scan."""


class ScanCancellationCheck:
    """Vérifie périodiquement en base si un scan a été annulé."""

    def __init__(self, scan_id: int, interval_seconds: float = 0.5):
        self.scan_id = scan_id
        self.interval_seconds = interval_seconds
        self._last_check = 0.0
        self._cancelled = False

    def __call__(self, force: bool = False) -> bool:
        now = time.monotonic()
        if force or now - self._last_check >= self.interval_seconds:
            self._cancelled = Scan.objects.filter(
                pk=self.scan_id, status=Scan.Status.CANCELLED,
            ).exists()
            self._last_check = now
        return self._cancelled

    def ensure_not_cancelled(self, force: bool = False) -> None:
        if self(force=force):
            raise ScanCancelled(f'Scan {self.scan_id} annulé par le propriétaire')
