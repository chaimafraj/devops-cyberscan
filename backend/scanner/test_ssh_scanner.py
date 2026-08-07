import os
from unittest.mock import Mock, mock_open, patch

from django.test import SimpleTestCase, override_settings

from .scan_cancellation import ScanCancelled
from .ssh_scanner import _run_local_command, run_sslscan, run_zap


class RunLocalCommandTests(SimpleTestCase):
    @patch('scanner.ssh_scanner.subprocess.Popen')
    def test_returns_stdout_stderr_and_exit_code(self, popen):
        process = popen.return_value
        process.communicate.return_value = (b'scanner output\n', b'warning\n')
        process.returncode = 3

        stdout, stderr, exit_code = _run_local_command('scanner --flag', timeout=5)

        self.assertEqual(stdout, 'scanner output\n')
        self.assertEqual(stderr, 'warning\n')
        self.assertEqual(exit_code, 3)
        popen.assert_called_once_with(
            'scanner --flag',
            shell=True,
            stdout=-1,
            stderr=-1,
            start_new_session=(os.name == 'posix'),
        )

    @patch('scanner.ssh_scanner._terminate_process')
    @patch('scanner.ssh_scanner.time.monotonic', side_effect=[10.0, 12.0])
    @patch('scanner.ssh_scanner.subprocess.Popen')
    def test_terminates_process_when_command_exceeds_timeout(
        self, popen, _monotonic, terminate_process,
    ):
        process = popen.return_value
        process.poll.return_value = None
        process.communicate.return_value = (b'', b'')

        with self.assertRaisesRegex(TimeoutError, '1 secondes'):
            _run_local_command('blocked command', timeout=1)

        terminate_process.assert_called_once_with(process)

    @patch('scanner.ssh_scanner._terminate_process')
    @patch('scanner.ssh_scanner.subprocess.Popen')
    def test_cancellation_terminates_process_and_runs_cleanup(self, popen, terminate_process):
        process = popen.return_value
        process.poll.return_value = None
        cleanup = Mock()

        with self.assertRaises(ScanCancelled):
            _run_local_command(
                'docker run zap',
                timeout=60,
                cancel_check=Mock(return_value=True),
                on_cancel=cleanup,
            )

        cleanup.assert_called_once_with()
        terminate_process.assert_called_once_with(process)


class RunZapTests(SimpleTestCase):
    @patch('scanner.ssh_scanner.os.remove')
    @patch('scanner.ssh_scanner.open', new_callable=mock_open, read_data='{"site": []}')
    @patch('scanner.ssh_scanner.os.path.isfile', return_value=True)
    @patch('scanner.ssh_scanner._run_local_command', return_value=('', '', 0))
    def test_mounts_and_removes_temporary_work_volume(
        self, run_command, _isfile, _report_file, remove_file,
    ):
        result = run_zap('https://app.example.test')

        self.assertTrue(result['success'])
        commands = [call.args[0] for call in run_command.call_args_list]
        volume_init_command = next(
            command for command in commands
            if command.startswith('docker run --rm --user root')
        )
        self.assertIn('--mount type=volume,src=cyberscan-zap-work-', volume_init_command)
        self.assertTrue(volume_init_command.endswith('chown zap:zap /zap/wrk'))
        scan_command = next(command for command in commands if command.startswith('docker run --name'))
        self.assertIn('--mount type=volume,src=cyberscan-zap-work-', scan_command)
        self.assertIn(',dst=/zap/wrk', scan_command)
        self.assertTrue(any(
            command.startswith('docker volume rm -f cyberscan-zap-work-')
            for command in commands
        ))
        remove_file.assert_called_once()

    @patch('scanner.ssh_scanner.os.remove', side_effect=FileNotFoundError)
    @patch('scanner.ssh_scanner._run_local_command', side_effect=[
        ('', '', 0),
        ('', '', 0),
        ('', 'volume permission failure', 1),
        ('', '', 0),
        ('', '', 0),
    ])
    def test_reports_volume_initialization_error_and_cleans_up(
        self, run_command, _remove_file,
    ):
        result = run_zap('https://app.example.test')

        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'volume permission failure')
        commands = [call.args[0] for call in run_command.call_args_list]
        self.assertTrue(any(
            command.startswith('docker volume rm -f cyberscan-zap-work-')
            for command in commands
        ))


@override_settings(SCANNER_COMMAND_TIMEOUT=60)
class RunSslscanRetryTests(SimpleTestCase):
    @patch('scanner.ssh_scanner._run_local_command')
    def test_global_timeout_stops_without_retrying(self, run_command):
        run_command.return_value = ('partial output', '', 124)

        result = run_sslscan('slow.example')

        self.assertFalse(result['success'])
        self.assertIn('sslscan', result['error'])
        self.assertEqual(run_command.call_count, 1)
        local_command = run_command.call_args.args[0]
        self.assertIn('timeout --signal=TERM', local_command)
        self.assertIn('--ipv4', local_command)

    @patch('scanner.ssh_scanner._run_local_command', side_effect=ScanCancelled('cancelled'))
    def test_propagates_cancellation_to_running_command(self, run_command):
        cancel_check = Mock(return_value=True)

        with self.assertRaises(ScanCancelled):
            run_sslscan('esprit.tn', cancel_check=cancel_check)

        self.assertIs(run_command.call_args.kwargs['cancel_check'], cancel_check)

    @patch('scanner.ssh_scanner.time.sleep')
    @patch('scanner.ssh_scanner._run_local_command')
    def test_retries_timeout_then_returns_success(self, run_command, sleep):
        run_command.side_effect = [
            ('', 'connect timeout', 1),
            ('Version: 2.1.5\nConnected to 196.203.216.18\n', '', 0),
        ]

        result = run_sslscan('esprit.tn')

        self.assertTrue(result['success'])
        self.assertEqual(run_command.call_count, 2)
        sleep.assert_called_once_with(2)

    @patch('scanner.ssh_scanner.time.sleep')
    @patch('scanner.ssh_scanner._run_local_command')
    def test_does_not_retry_non_transient_dns_error(self, run_command, sleep):
        run_command.return_value = ('', 'Could not resolve hostname', 1)

        result = run_sslscan('missing.example')

        self.assertFalse(result['success'])
        self.assertIn('DOMAINE INTROUVABLE', result['error'])
        run_command.assert_called_once()
        sleep.assert_not_called()

    @patch('scanner.ssh_scanner.time.sleep')
    @patch('scanner.ssh_scanner._run_local_command')
    def test_returns_timeout_after_three_attempts(self, run_command, sleep):
        run_command.return_value = ('', 'connection timed out', 1)

        result = run_sslscan('slow.example')

        self.assertFalse(result['success'])
        self.assertIn('TIMEOUT', result['error'])
        self.assertEqual(run_command.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
