"""Synthetic endpoints only; no host socket fixtures."""
import io
import contextlib
import json
import unittest

from faultlens.cli import main
from faultlens.commands import CATALOG, Command, Result
from faultlens.sockets import attach, parse
from tests.test_network_analysis import NetworkSources


class SocketRunner:
    def __init__(self, result=None):
        self.result = result or Result('completed', 'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n', 0)
        self.calls = []

    def run(self, command):
        self.calls.append(command)
        return self.result


class SocketTests(unittest.TestCase):
    def test_numeric_endpoints_and_originals(self):
        text = 'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\nudp UNCONN 1 2 [fe80::1%synthetic0]:53 [::]:*\ntcp ESTAB 3 4 [::1]:12345 [2001:db8::1]:443\n'
        rows = parse(text)
        self.assertEqual(3, len(rows))
        self.assertEqual('fe80::1%synthetic0', rows[1]['local']['address'])
        self.assertEqual(443, rows[2]['peer']['port'])
        self.assertIsNone(rows[0]['peer']['port'])
        self.assertEqual(text.splitlines(), [r['original'] for r in rows])
        self.assertEqual(3, rows[2]['receive_queue'])

    def test_device_bound_ipv4_and_ipv6_bracket_layouts(self):
        for address in ('192.0.2.1%synthetic0', '[fe80::1]%synthetic0', '[fe80::1%synthetic0]'):
            rows = parse(f'udp UNCONN 0 0 {address}:53 *:*')
            self.assertTrue(rows[0]['local']['address'].endswith('%synthetic0'))
            self.assertEqual(address+':53', rows[0]['local']['original'])

    def test_empty_and_duplicate_rows_are_legitimate(self):
        self.assertEqual([], parse(''))
        row = 'udp UNCONN 0 0 *:53 *:*\n'
        self.assertEqual(2, len(parse(row * 2)))
        self.assertEqual(512, len(parse(row * 512)))

    def test_rejects_unsupported_or_over_limit_data(self):
        good = 'tcp LISTEN 0 128 127.0.0.1:2222 0.0.0.0:*'
        for value in (good * 20000, (good+'\n')*513, good+' extra', '\n',
                      good.replace('LISTEN', 'FUTURE'), good.replace('127.0.0.1', 'example.test'),
                      good.replace(':2222', ':65536'), good.replace(' 128 ', ' -1 '),
                      good.replace(' 128 ', ' 18446744073709551616 '),
                      good.replace('127.0.0.1', '127.0.0.1%bad/zone'),
                      good.replace('127.0.0.1', '[::1%bad/zone]'), good+'\x1b', good+'\r', good+'\u2028', good+'\x7f'):
            with self.subTest(value=value[:100]), self.assertRaises(ValueError):
                parse(value)

    def test_fixed_read_only_command(self):
        self.assertEqual(('ss', ('-H', '-n', '-O', '-a', '-t', '-u')), CATALOG[Command.SOCKETS])

    def test_failure_never_presents_a_successful_prefix(self):
        for result in (Result('missing'), Result('timeout', 'tcp LISTEN 0 1 *:22 *:*', None),
                       Result('completed', '', 1), Result('completed', 'tcp LISTEN 0 1 *:22 *:*\nbad', 0)):
            data = {'state': 'available', 'limitations': []}
            attach(data, SocketRunner(result))
            self.assertEqual('partial', data['state'])
            self.assertEqual('unavailable', data['sockets']['state'])
            self.assertEqual([], data['sockets']['rows'])

    def test_available_sockets_with_missing_counters_are_partial(self):
        data = {'state': 'unavailable', 'limitations': []}
        attach(data, SocketRunner())
        self.assertEqual('partial', data['state'])
        self.assertEqual('available', data['sockets']['state'])

    def test_cli_opt_in_and_text_have_unmasked_endpoints(self):
        for command in ('network', 'security'):
            for json_mode in (False, True):
                runner, output = SocketRunner(), io.StringIO()
                arguments = [command, '--sockets', '--sample-seconds', '0.05'] + (['--json'] if json_mode else [])
                self.assertEqual(0, main(arguments, sources=NetworkSources(), runner=runner, stdout=output))
                self.assertIn('0.0.0.0:2222', output.getvalue())
                self.assertEqual([Command.SOCKETS], runner.calls)
                if json_mode:
                    self.assertEqual('Unknown', json.loads(output.getvalue())['attack_assessment'])
        runner = SocketRunner()
        main(['network', '--json'], sources=NetworkSources(), runner=runner, stdout=io.StringIO())
        self.assertEqual([], runner.calls)

    def test_flag_rejected_for_other_commands(self):
        for command in ('status', 'check', 'diagnose', 'history', 'incidents'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                main([command, '--sockets'], stdout=io.StringIO(), stderr=io.StringIO())
            self.assertEqual(2, caught.exception.code)
