"""Invented extended Atop rows; no process names or host recordings in fixtures."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.atop import samples, window_boundary
from faultlens.cli import main
from faultlens.commands import Result
from faultlens.incidents import diagnose
from tests.test_atop import AtopRunner, EPOCH, sample


def extended_sample(*, reset=False, rows=None):
    text = sample(reset=reset)
    header = text.split('CPU ', 1)[1].splitlines()[0].split()[:5]
    if rows is None:
        rows = [
            ('DSK', 'syntheticdisk 5 2 4 3 6 -1 -1 0 0.50'),
            ('NET', 'upper ' + ' '.join(map(str, range(1, 18)))),
            ('NET', 'syntheticnic 10 1024 20 2048 1000 1 1 2 3 4 0 0 0 0 0 0 0 0'),
            ('PRC', '42 private-process S 100 200 100 0 20 0 0 0 0 42 y 5 private-wchan 6 -3 -2 7 8'),
            ('PRM', '42 private-process S 4096 40 20 4 -1 -1 2 3 4 5 6 7 42 y 0 0 -3 -2 -3 -2')]
    suffix = '\n'.join(label + ' ' + ' '.join(header) + ' ' + value for label, value in rows)
    return text.replace('SEP\n', suffix + '\nSEP\n')


class ExtendedRunner(AtopRunner):
    def __init__(self, text=None):
        super().__init__()
        self.extended_result = Result('completed', extended_sample() if text is None else text, 0)
        self.extended_calls = []

    def read_atop_extended(self, date, start, end):
        self.extended_calls.append((date, start, end))
        return self.extended_result


class ExtendedAtopTests(unittest.TestCase):
    def test_checked_units_and_protocol_fields_have_no_names_or_pids(self):
        value, = samples(extended_sample(), extended=True)
        extra = value['extended']
        self.assertEqual(2048, extra['disks'][0]['read_bytes'])
        self.assertEqual(3072, extra['disks'][0]['write_bytes'])
        self.assertEqual(3, extra['interfaces'][0]['receive_drops'])
        self.assertEqual(13, extra['network_protocols']['tcp_established_snapshot'])
        self.assertEqual(3, extra['processes']['cpu_seconds'])
        self.assertEqual(20480, extra['processes']['resident_bytes_sum_snapshot'])
        self.assertEqual(7168, extra['processes']['swap_bytes_sum_snapshot'])
        self.assertEqual(3, extra['processes']['major_page_faults'])
        for marker in ('private-process', 'private-wchan', 'syntheticdisk', 'syntheticnic', 'synthetic.test'):
            self.assertNotIn(marker, json.dumps(value))

    def test_basic_profile_rejects_extended_rows_instead_of_silent_collection(self):
        with self.assertRaises(ValueError):
            samples(extended_sample())
        runner = ExtendedRunner()
        data = diagnose(runner, atop_date='20260101')
        self.assertEqual('basic', data['atop']['profile'])
        self.assertEqual([], runner.extended_calls)
        self.assertEqual(1, len(runner.atop_calls))

    def test_explicit_extended_profile_preserves_temporal_only_pairing(self):
        runner = ExtendedRunner()
        data = diagnose(runner, atop_date='20260101', atop_extended=True)
        self.assertEqual('available', data['atop']['state'])
        self.assertEqual('extended', data['atop']['profile'])
        self.assertEqual([], runner.atop_calls)
        self.assertEqual(1, len(runner.extended_calls))
        self.assertEqual('Unknown', data['root_cause'])
        self.assertEqual('Possible', data['atop']['correlations'][0]['confidence'])
        self.assertEqual('unverified', data['atop']['boot_identity'])

    def test_reset_is_validated_but_never_interpreted_as_interval_activity(self):
        value, = samples(extended_sample(reset=True), extended=True)
        self.assertEqual('since_boot_aggregate_excluded', value['extended']['state'])
        self.assertEqual([], value['extended']['disks'])
        self.assertIsNone(value['extended']['processes'])
        data = diagnose(ExtendedRunner(extended_sample(reset=True)), atop_date='20260101', atop_extended=True)
        self.assertEqual([], data['atop']['correlations'])

    def test_threads_and_exited_process_memory_are_not_double_counted(self):
        text = extended_sample().replace('42 y', '42 n')
        process = samples(text, extended=True)[0]['extended']['processes']
        self.assertEqual(0, process['reported_processes'])
        self.assertEqual(1, process['excluded_thread_rows'])
        text = extended_sample().replace('private-process S', 'private-process E')
        process = samples(text, extended=True)[0]['extended']['processes']
        self.assertEqual(1, process['reported_exited_processes'])
        self.assertEqual(0, process['resident_bytes_sum_snapshot'])
        self.assertEqual(0, process['cpu_seconds'])
        self.assertEqual(0, process['major_page_faults'])

    def test_missing_process_halves_mixed_units_and_malformed_rows_fail_closed(self):
        text = extended_sample()
        cases = [text.replace('PRM ', 'UNKNOWN '), text.replace('S 4096 40', 'S 8192 40'),
                 text.replace('S 100 200', 'S 99 200'), text.replace('S 100 200', 'S 100 -200'),
                 text.replace('42 private-process S 4096', '43 private-process S 4096'),
                 text.replace('private-wchan', 'private\x1bwchan'),
                 text.replace('private-process S 4096', 'different-process S 4096'),
                 text.replace('0.50', 'NaN'), text.replace('0.50', '0.50 trailing'),
                 text.replace('syntheticnic 10', 'syntheticnic -10'), text.replace('SEP\n', '')]
        cases.append('\n'.join(line for line in text.splitlines() if not line.startswith('PRM ')) + '\n')
        for value in cases:
            with self.subTest(value=value[:30]), self.assertRaises(ValueError):
                samples(value, extended=True)

    def test_duplicates_and_partial_groups_do_not_create_resource_totals(self):
        text = extended_sample()
        for prefix in ('DSK ', 'NET ', 'PRC ', 'PRM '):
            line = next(line for line in text.splitlines() if line.startswith(prefix))
            with self.assertRaises(ValueError):
                samples(text.replace('SEP\n', line + '\nSEP\n'), extended=True)
        for prefix in ('NET ', 'CPU '):
            with self.assertRaises(ValueError):
                samples('\n'.join(line for line in text.splitlines() if not line.startswith(prefix)), extended=True)

    def test_absent_device_process_rows_are_explicit_not_proof_of_no_activity(self):
        value, = samples(extended_sample(rows=[('NET', 'upper ' + '0 ' * 16 + '0')]), extended=True)
        self.assertEqual('no_device_rows_reported', value['extended']['disk_coverage'])
        self.assertEqual('no_interface_rows_reported', value['extended']['interface_coverage'])
        self.assertEqual('reported_rows_only', value['extended']['processes']['coverage'])

    def test_device_and_process_limits_reject_entire_response(self):
        disks = [('DSK', f'disk{index} 0 0 0 0 0 -1 -1 0 0.00') for index in range(33)]
        with self.assertRaises(ValueError):
            samples(extended_sample(rows=disks + [('NET', 'upper ' + '0 ' * 16 + '0')]), extended=True)
        processes = []
        for index in range(257):
            pid = index + 1
            processes += [('PRC', f'{pid} private S 100 0 0 0 20 0 0 0 0 {pid} y 0 _ 0 -3 -2 0 0'),
                          ('PRM', f'{pid} private S 4096 0 0 0 0 0 0 0 0 0 0 0 {pid} y 0 0 -3 -2 -3 -2')]
        with self.assertRaises(ValueError):
            samples(extended_sample(rows=processes + [('NET', 'upper ' + '0 ' * 16 + '0')]), extended=True)

    def test_unavailable_extended_replay_preserves_journal_findings_without_retry(self):
        for result in (Result('timeout'), Result('output_limit'), Result('completed', 'private details', 1),
                       Result('completed', sample(), 0)):
            runner = ExtendedRunner()
            runner.extended_result = result
            data = diagnose(runner, atop_date='20260101', atop_extended=True)
            self.assertEqual('unavailable', data['atop']['state'])
            self.assertEqual(1, len(data['findings']))
            self.assertEqual([], runner.atop_calls)
            self.assertNotIn('private details', json.dumps(data))

    def test_window_stops_only_after_complete_validated_extended_sample(self):
        text = extended_sample()
        self.assertEqual(len(text), window_boundary(bytearray(text.encode()), EPOCH+30, extended=True))
        self.assertIsNone(window_boundary(bytearray(text.encode()), EPOCH+60, extended=True))
        with self.assertRaises(ValueError):
            window_boundary(bytearray(text.replace('PRM ', 'BAD ').encode()), EPOCH+30, extended=True)

    def test_cli_requires_explicit_date_and_omits_private_resource_labels(self):
        for args in (['diagnose', '--atop-extended'], ['incidents', '--atop-extended'],
                     ['status', '--atop-extended', '--atop-date', '20260101']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)
        with self.assertRaises(ValueError):
            diagnose(ExtendedRunner(), atop_extended=True)
        output = io.StringIO()
        self.assertEqual(0, main(['diagnose', '--atop-date', '20260101', '--atop-extended', '--json'],
                                runner=ExtendedRunner(), stdout=output))
        self.assertNotIn('private-process', output.getvalue())
        self.assertEqual('extended', json.loads(output.getvalue())['atop']['profile'])

    def test_helper_rejects_arbitrary_profile_before_any_native_execution(self):
        from faultlens import _atop_exec
        with patch('faultlens._atop_exec.os.execve', side_effect=AssertionError('must not execute')):
            self.assertEqual(125, _atop_exec.main(['/usr/bin/atop', '3', '20260101000000', '20260101000100', 'ALL']))


class ExtendedExecutionTests(unittest.TestCase):
    def test_fixed_extended_profile_uses_the_existing_isolated_helper_guards(self):
        import subprocess
        import sys
        import tempfile
        from pathlib import Path
        script = """import ctypes,json,sys
sys.path.insert(0, sys.argv[1])
from faultlens import _atop_exec as helper
def inspect(executable, arguments, environment):
 print(json.dumps({'labels':arguments[4], 'space_flag':'-Z' in arguments, 'nnp':ctypes.CDLL(None).prctl(39,0,0,0,0)}))
 raise SystemExit(0)
helper.os.execve=inspect
helper.main(['/usr/bin/atop',sys.argv[2],'20260101000000','20260101000100','extended'])
"""
        with tempfile.TemporaryFile() as file:
            result = subprocess.run([sys.executable, '-I', '-c', script,
                str(Path(__file__).resolve().parents[1]), str(file.fileno())],
                pass_fds=(file.fileno(),), capture_output=True, text=True, timeout=5, check=True)
        value = json.loads(result.stdout)
        self.assertEqual('CPU,MEM,SWP,DSK,NET,PRC,PRM', value['labels'])
        self.assertTrue(value['space_flag'])
        self.assertEqual(1, value['nnp'])
