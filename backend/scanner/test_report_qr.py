from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

from .report_fixed import _draw_history_qr, _history_url, _report_page


class ReportHistoryQrTests(SimpleTestCase):
    @override_settings(CYBERSCAN_HISTORY_URL='https://cyberscan.example/historique')
    def test_history_url_uses_configured_destination(self):
        self.assertEqual(_history_url(), 'https://cyberscan.example/historique')

    @override_settings(
        CYBERSCAN_HISTORY_URL='',
        CYBERSCAN_SITE_URL='https://cyberscan.example/app/',
    )
    def test_history_url_falls_back_to_site_history_route(self):
        self.assertEqual(_history_url(), 'https://cyberscan.example/app/historique')

    @patch('scanner.report_fixed._draw_history_qr')
    @patch('scanner.report_fixed._header_footer')
    def test_qr_is_only_drawn_on_first_page(self, header_footer, draw_qr):
        canvas = Mock()
        doc = SimpleNamespace(page=1, history_url='https://cyberscan.example/historique')

        _report_page(canvas, doc)
        doc.page = 2
        _report_page(canvas, doc)

        self.assertEqual(header_footer.call_count, 2)
        draw_qr.assert_called_once_with(canvas, 'https://cyberscan.example/historique')

    @patch('scanner.report_fixed.Drawing')
    @patch('scanner.report_fixed.QrCodeWidget')
    def test_qr_widget_encodes_history_url(self, qr_widget, drawing):
        widget = qr_widget.return_value
        widget.getBounds.return_value = (0, 0, 100, 100)
        canvas = Mock()
        history_url = 'https://cyberscan.example/historique'

        _draw_history_qr(canvas, history_url)

        qr_widget.assert_called_once_with(history_url)
