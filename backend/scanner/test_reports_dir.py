import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from .report_generator import _reports_dir


class ReportsDirTests(SimpleTestCase):
    def test_creates_missing_media_and_rapports_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            media_root = Path(tmp) / 'media'
            reports_dir = media_root / 'rapports'
            self.assertFalse(media_root.exists())

            with override_settings(MEDIA_ROOT=media_root, REPORTS_DIR=reports_dir):
                result = _reports_dir()

            self.assertEqual(result, reports_dir)
            self.assertTrue(reports_dir.is_dir())
            self.assertTrue(media_root.is_dir())

    def test_raises_clear_error_when_directory_is_not_writable(self):
        with tempfile.TemporaryDirectory() as tmp:
            media_root = Path(tmp) / 'media'
            reports_dir = media_root / 'rapports'
            media_root.mkdir(parents=True)
            reports_dir.mkdir(parents=True)

            with override_settings(MEDIA_ROOT=media_root, REPORTS_DIR=reports_dir):
                with patch('scanner.report_generator.os.access', return_value=False):
                    with self.assertRaises(RuntimeError) as ctx:
                        _reports_dir()

            self.assertIn('accessible en écriture', str(ctx.exception))
