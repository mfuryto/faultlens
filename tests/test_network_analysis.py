"""Invented network counters only; no packets, endpoint collection or host traffic."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.network import TCP_FIELDS, collect, tcp_extensions
from tests.support import SyntheticSources

HEADER = 'Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n'


def device(name='synthetic0', received=100, sent=200):
    return f'{name}: {received} 10 0 0 0 0 0 0 {sent} 20 0 0 0 0 0 0\n'


def stats(values=(0, 0, 0, 0, 0)):
    return 'TcpExt: ' + ' '.join(TCP_FIELDS) + '\nTcpExt: ' + ' '.join(map(str, values)) + '\n'


class NetworkSources:
    def __init__(self, devices=None, tcp=None):
        self.values = {'/proc/net/dev': devices or [HEADER+device(), HEADER+device(received=200, sent=400)],
                       '/proc/net/netstat': tcp or [stats(), stats()]}
        self.reads = {}

    def read(self, path):
        index = self.reads.get(path, 0)
        self.reads[path] = index+1
        value = self.values[path][index]
        if isinstance(value, Exception):
            raise value
        return value


def analyze(sources=None, *, times=(10, 10.5), **kwargs):
    clock = iter(times)
    return collect(sources or NetworkSources(), sleep=lambda _: None, clock=lambda: next(clock), **kwargs)


class NetworkAnalysisTests(unittest.TestCase):
    def test_actual_interval_not_requested_sleep_controls_rates(self):
        data = analyze(sample_seconds=0.1)
        observation = data['observations'][0]['value'][0]
        self.assertEqual(100, observation['delta']['received_bytes'])
        self.assertEqual(200, observation['per_second']['received_bytes'])
        self.assertEqual(0.5, data['sample']['elapsed_seconds'])
        self.assertEqual('available', data['state'])
        self.assertEqual('Unknown', data['attack_assessment'])
        self.assertEqual([], data['findings'])

    def test_positive_security_counters_confirm_growth_not_attacks(self):
        data = analyze(NetworkSources(tcp=[stats((100, 20, 2, 10, 10)), stats((102, 20, 2, 13, 14))]), command='security')
        self.assertEqual(3, len(data['findings']))
        self.assertEqual('security', data['command'])
        for value in data['findings']:
            self.assertEqual('Confirmed', value['confidence'])
            self.assertEqual('Unknown', value['cause_confidence'])
            self.assertEqual({'minimum_counter_delta': 1}, value['thresholds'])
            self.assertTrue(value['recommendations'])
        self.assertEqual('Unknown', data['attack_assessment'])
        self.assertEqual('Unknown', data['root_cause'])

    def test_large_existing_totals_without_growth_never_become_findings(self):
        data = analyze(NetworkSources(tcp=[stats((999999, 0, 0, 999999, 999999))]*2))
        self.assertEqual([], data['findings'])
        self.assertEqual('Unknown', data['attack_assessment'])

    def test_resets_and_interface_changes_preserve_unknown_rates(self):
        before = HEADER+device('reset')+device('removed')
        after = HEADER+device('reset', received=1)+device('added')
        data = analyze(NetworkSources(devices=[before, after]))
        self.assertEqual('partial', data['state'])
        values = data['observations'][0]['value']
        self.assertEqual(3, len(values))
        self.assertTrue(all(value['per_second'] is None for value in values))

    def test_source_failure_is_independent_and_private_error_is_not_echoed(self):
        data = analyze(NetworkSources(devices=[PermissionError('private-interface'), HEADER+device()],
                                      tcp=[stats(), stats((1, 0, 0, 0, 0))]))
        self.assertEqual('partial', data['state'])
        self.assertEqual(1, len(data['findings']))
        self.assertNotIn('private-interface', json.dumps(data))

    def test_missing_fields_and_decreasing_tcp_counters_are_unavailable(self):
        partial = 'TcpExt: ListenDrops\nTcpExt: 1\n'
        data = analyze(NetworkSources(tcp=[partial, partial]))
        self.assertEqual('partial', data['state'])
        self.assertEqual(4, sum(value['state'] == 'unavailable' for value in data['observations']))
        data = analyze(NetworkSources(tcp=[stats((2, 0, 0, 0, 0)), stats((1, 0, 0, 0, 0))]))
        self.assertEqual([], data['findings'])
        self.assertEqual('unavailable', data['observations'][1]['state'])

    def test_invalid_clock_and_all_failed_sources_do_not_fabricate_rates(self):
        for times in ((10, 10), (10, 9), (10, 16), (10, float('nan'))):
            self.assertEqual('unavailable', analyze(times=times)['state'])
        sources = NetworkSources(devices=[OSError('private')]*2, tcp=[OSError('private')]*2)
        data = analyze(sources)
        self.assertEqual('unavailable', data['state'])
        self.assertEqual([], data['findings'])

    def test_tcp_parser_validates_all_pairs_without_echoing_unknown_fields(self):
        for text in (stats()+stats(), 'TcpExt: ListenDrops ListenDrops\nTcpExt: 1 2\n',
                     'TcpExt: ListenDrops\nOther: 1\n', 'TcpExt: ListenDrops\nTcpExt: -1\n',
                     stats()+'dangling', 'x'*262145, 'TcpExt: private-field\nTcpExt: 1\n'):
            with self.assertRaises(ValueError):
                tcp_extensions(text)
        value = tcp_extensions('TcpExt: ListenDrops SyntheticUnknown\nTcpExt: 2 7\n')
        self.assertEqual(2, value['ListenDrops'])
        self.assertNotIn('SyntheticUnknown', value)

    def test_duplicate_unsafe_or_excessive_interfaces_fail_closed(self):
        for text in (HEADER.replace('multicast|bytes', 'changed|bytes')+device(), HEADER+device()+device(), HEADER+device('bad\x1bname'),
                     HEADER+''.join(device('nic'+str(i)) for i in range(129))):
            data = analyze(NetworkSources(devices=[text, text]))
            self.assertEqual('unavailable', data['observations'][0]['state'])

    def test_invalid_sampling_fails_before_any_read(self):
        sources = NetworkSources()
        for value in (0, 2, True, float('nan'), float('inf'), '0.1'):
            with self.assertRaises(ValueError):
                analyze(sources, sample_seconds=value)
        self.assertEqual({}, sources.reads)

    def test_cli_is_local_and_rejects_unrelated_feature_flags(self):
        for command in ('network', 'security'):
            output = io.StringIO()
            with patch('socket.socket', side_effect=AssertionError('no sockets')), patch(
                    'subprocess.Popen', side_effect=AssertionError('no native tools')), patch(
                    'builtins.open', side_effect=AssertionError('no files')):
                self.assertEqual(0, main([command, '--sample-seconds', '0.05', '--json'], sources=NetworkSources(), stdout=output))
            self.assertEqual(command, json.loads(output.getvalue())['command'])
            for flag in ('--system-journal', '--search-events', '--pstore', '--history'):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    main([command, flag])

    def test_text_output_explains_security_uncertainty_and_counter_evidence(self):
        output = io.StringIO()
        main(['security', '--sample-seconds', '0.05'], sources=NetworkSources(tcp=[stats(), stats((1, 0, 0, 0, 0))]), stdout=output)
        self.assertIn('Confirmed counter growth; attack Unknown', output.getvalue())
        self.assertIn('Evidence:', output.getvalue())
