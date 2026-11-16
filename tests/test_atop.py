"""Invented Atop records and isolated boundary tests; no host recordings or native Atop."""
import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from faultlens import _atop_exec
from faultlens.atop import MAX_SAMPLES, samples, window_boundary
from faultlens.cli import main
from faultlens.commands import CommandRunner, Result, _capture
from faultlens.incidents import diagnose
from faultlens.recordings import MAX_RECORDING_BYTES, open_recording, recording_date, trusted_metadata
from tests.test_incidents import JournalRunner, record

EPOCH = 1767225600


def sample(timestamp=EPOCH + 30, period=30, *, reset=False, host='synthetic.test'):
    moment = datetime.fromtimestamp(timestamp, timezone.utc)
    suffix = f'{host} {timestamp} {moment:%Y/%m/%d} {moment:%H:%M:%S} {period}'
    rows = [('CPU', f'100 1 {10*period} {10*period} 0 {80*period} 0 0 0 0 {50*period}'),
            ('MEM', '4096 1000 400 300'), ('SWP', '4096 100 25')]
    return ('RESET\n' if reset else '') + '\n'.join(label + ' ' + suffix + ' ' + values for label, values in rows) + '\nSEP\n'


class AtopRunner(JournalRunner):
    def __init__(self, records=None, text=None):
        super().__init__(records if records is not None else [record('Out of memory: Killed process 42',
                         realtime=(EPOCH + 15) * 1000000, monotonic=15000000)])
        self.atop_result = Result('completed', sample() if text is None else text, 0)
        self.atop_calls = []

    def read_atop(self, date, start, end):
        self.atop_calls.append((date, start, end))
        return self.atop_result


class AtopParserTests(unittest.TestCase):
    def test_units_guest_exclusion_and_recorded_hostname(self):
        value, = samples(sample())
        self.assertEqual(20, value['cpu_busy_percent'])
        self.assertEqual(4096000, value['memory_total_bytes'])
        self.assertEqual(1638400, value['memory_free_bytes'])
        self.assertEqual(307200, value['swap_used_bytes'])
        self.assertEqual('synthetic.test', value['recorded_hostname'])
        self.assertNotIn('memory_used_percent', value)

    def test_reset_and_zero_ticks_are_not_localized_cpu_measurements(self):
        self.assertIsNone(samples(sample(reset=True))[0]['cpu_busy_percent'])
        text = sample().replace('300 300 0 2400 0 0 0 0 1500', '0 0 0 0 0 0 0 0 0')
        self.assertIsNone(samples(text)[0]['cpu_busy_percent'])
        self.assertIsNone(samples(sample(period=100000, reset=True))[0]['cpu_busy_percent'])

    def test_truncation_duplicates_mixed_hosts_and_bad_numeric_data_fail_closed(self):
        value = sample()
        for text in (value.replace('SEP\n', ''), value.replace('CPU ', 'PRG ', 1),
                     value.replace('MEM synthetic.test', 'MEM different.test'),
                     value.replace('4096 1000 400', '4096 1000 1001'),
                     value.replace('SWP', 'CPU'), value.replace('100 1 300', '100 1 NaN'),
                     value.replace('2026/01/01', '2026/01/02'), 'RESET\n', value + value):
            with self.subTest(text=text[:40]), self.assertRaises(ValueError):
                samples(text)

    def test_output_and_sample_caps_are_enforced(self):
        with self.assertRaises(ValueError):
            samples('x' * 262145)
        with self.assertRaises(ValueError):
            samples(''.join(sample(EPOCH + index + 1, period=1) for index in range(MAX_SAMPLES + 1)))

    def test_no_swap_is_a_valid_zero(self):
        value, = samples(sample().replace('4096 100 25', '4096 0 0'))
        self.assertEqual(0, value['swap_used_bytes'])


class CorrelationTests(unittest.TestCase):
    def test_opt_in_temporal_overlap_never_becomes_a_confirmed_cause(self):
        runner = AtopRunner()
        data = diagnose(runner, atop_date='20260101')
        self.assertEqual('available', data['atop']['state'])
        self.assertEqual('Unknown', data['root_cause'])
        pair, = data['atop']['correlations']
        self.assertEqual('Possible', pair['confidence'])
        self.assertEqual('Unknown', pair['cause_confidence'])
        self.assertEqual('unverified', data['atop']['boot_identity'])
        self.assertEqual('synthetic.test', data['atop']['samples'][0]['recorded_hostname'])
        _, start, end = runner.atop_calls[0]
        self.assertEqual(7200, end - start)

    def test_correlation_cap_is_reported_without_changing_event_confidence(self):
        records = [record('Out of memory: Killed process 42', realtime=(EPOCH + 15) * 1000000,
                          monotonic=15000000) for _ in range(500)]
        runner = AtopRunner(records=records, text=sample(EPOCH + 20) + sample(EPOCH + 21))
        data = diagnose(runner, atop_date='20260101')
        self.assertTrue(data['atop']['correlation_limit_reached'])
        self.assertEqual(500, len(data['atop']['correlations']))
        self.assertTrue(all(finding['confidence'] == 'Confirmed' for finding in data['findings']))
        self.assertEqual('Unknown', data['root_cause'])

    def test_ten_minute_recording_interval_is_supported_without_inventing_precision(self):
        runner = AtopRunner(text=sample(EPOCH + 600, period=600))
        data = diagnose(runner, atop_date='20260101')
        self.assertEqual('available', data['atop']['state'])
        self.assertEqual(600, data['atop']['samples'][0]['interval_s'])
        self.assertEqual('Possible', data['atop']['correlations'][0]['confidence'])
        self.assertEqual('Unknown', data['root_cause'])

    def test_validated_parent_window_completion_is_accepted(self):
        runner = AtopRunner()
        runner.atop_result = Result('window_complete', sample())
        data = diagnose(runner, atop_date='20260101')
        self.assertEqual('available', data['atop']['state'])
        self.assertEqual('window_complete', data['atop']['collection_state'])

    def test_default_analysis_never_reads_atop(self):
        runner = AtopRunner()
        self.assertEqual('not_requested', diagnose(runner)['atop']['state'])
        self.assertEqual([], runner.atop_calls)

    def test_no_journal_scope_or_clock_jump_prevents_native_collection(self):
        runner = AtopRunner(records=[])
        self.assertEqual('journal_scope_unavailable', diagnose(runner, atop_date='20260101')['atop']['reason'])
        self.assertEqual([], runner.atop_calls)
        runner = AtopRunner(records=[record(realtime=(EPOCH + 1) * 1000000, monotonic=1000000),
                                    record(realtime=(EPOCH + 20) * 1000000, monotonic=2000000)])
        self.assertEqual('ambiguous_journal_clock_mapping', diagnose(runner, atop_date='20260101')['atop']['reason'])
        self.assertEqual([], runner.atop_calls)

    def test_reset_out_of_window_and_missing_recordings_do_not_fabricate_overlap(self):
        for text in (sample(reset=True), sample(EPOCH - 4000)):
            data = diagnose(AtopRunner(text=text), atop_date='20260101')
            self.assertEqual([], data['atop']['correlations'])
        runner = AtopRunner()
        for result in (Result('missing'), Result('timeout'), Result('output_limit'), Result('completed', 'unsupported', 0)):
            runner.atop_result = result
            data = diagnose(runner, atop_date='20260101')
            self.assertEqual('unavailable', data['atop']['state'])
            self.assertEqual('Confirmed', data['findings'][0]['confidence'])

    def test_cli_rejects_paths_and_invalid_or_misplaced_dates(self):
        for args in (['diagnose', '--atop-date', '../../private'], ['diagnose', '--atop-date', '20260230'],
                     ['status', '--atop-date', '20260101'], ['diagnose', '--atop-date', '19690101']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                main(args)
            self.assertEqual(2, result.exception.code)


class RecordingBoundaryTests(unittest.TestCase):
    def test_recording_date_is_checked_before_any_filesystem_access(self):
        for date in ('../private', '20260230', '20260101.gz', '2026010', None):
            with patch('faultlens.recordings.os.open', side_effect=AssertionError('must not open')):
                with self.assertRaises((ValueError, TypeError)):
                    open_recording(date)
        self.assertEqual('20260101', recording_date('20260101'))

    def test_untrusted_metadata_is_rejected(self):
        for uid, mode, size in ((1000, stat.S_IFREG | 0o644, 10),
                                (0, stat.S_IFREG | 0o666, 10), (0, stat.S_IFIFO | 0o600, 10),
                                (0, stat.S_IFREG | 0o600, MAX_RECORDING_BYTES + 1),
                                (0, stat.S_IFREG | 0o600, 0)):
            with self.subTest(uid=uid, mode=mode, size=size), self.assertRaises(ValueError):
                trusted_metadata(SimpleNamespace(st_uid=uid, st_mode=mode, st_size=size))

    def test_path_walk_pins_descriptors_and_never_follows_links(self):
        directory = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        file = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o640, st_size=100)
        with patch('faultlens.recordings.os.open', side_effect=[10,11,12,13,14]) as opened, patch(
                'faultlens.recordings.os.fstat', side_effect=[directory] * 4 + [file]), patch('faultlens.recordings.os.close') as closed:
            self.assertEqual(14, open_recording('20260101'))
        self.assertEqual(['/', 'var', 'log', 'atop', 'atop_20260101'], [call.args[0] for call in opened.call_args_list])
        self.assertTrue(all(call.args[1] & os.O_NOFOLLOW for call in opened.call_args_list))
        self.assertEqual([10,11,12,13], [call.args[0] for call in closed.call_args_list])
        self.assertTrue(opened.call_args_list[-1].args[1] & os.O_NONBLOCK)

    def test_only_the_pinned_log_parent_can_be_group_writable(self):
        metadata = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o775)
        trusted_metadata(metadata, directory=True, allow_group_write=True)
        with self.assertRaises(ValueError):
            trusted_metadata(metadata, directory=True)
        with self.assertRaises(ValueError):
            trusted_metadata(SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777),
                             directory=True, allow_group_write=True)

    def test_native_reader_closes_fd_and_uses_only_the_isolated_helper(self):
        with patch('faultlens.commands.trusted_tool', return_value='/usr/bin/atop'), patch(
                'faultlens.recordings.open_recording', return_value=14), patch('faultlens.commands.os.close') as closed, patch(
                'faultlens.commands._capture', return_value=Result('timeout')) as capture:
            self.assertEqual('timeout', CommandRunner().read_atop('20260101', EPOCH, EPOCH + 60).state)
        self.assertEqual((14,), capture.call_args.kwargs['pass_fds'])
        self.assertEqual('-I', capture.call_args.args[0][1])
        closed.assert_called_once_with(14)
        for start, end in ((-1, EPOCH), (EPOCH, EPOCH + 7201), (True, EPOCH)):
            with self.assertRaises(ValueError):
                CommandRunner().read_atop('20260101', start, end)

    def test_capture_closes_pipes_even_if_cleanup_fails(self):
        for failure in ('signal', 'reap'):
            child = subprocess.Popen([sys.executable, '-c', 'print("synthetic")'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            original_wait = child.wait
            try:
                with patch('faultlens.commands.subprocess.Popen', return_value=child), patch(
                        'faultlens.commands.os.killpg', side_effect=PermissionError if failure == 'signal' else ProcessLookupError), patch.object(
                        child, 'wait', side_effect=subprocess.TimeoutExpired('synthetic', 1)):
                    with self.assertRaises(PermissionError if failure == 'signal' else subprocess.TimeoutExpired):
                        _capture([sys.executable, '-c', 'unused'])
                self.assertTrue(child.stdout.closed)
                self.assertTrue(child.stderr.closed)
            finally:
                original_wait(timeout=5)

    def test_helper_cannot_be_used_to_launch_an_arbitrary_program(self):
        with patch('faultlens._atop_exec.os.execve', side_effect=AssertionError('must not exec')):
            self.assertEqual(125, _atop_exec.main(['/bin/sh', '3', '20260101000000', '20260101000100']))

    def test_helper_fails_closed_if_privilege_guard_is_unavailable(self):
        library = SimpleNamespace(prctl=lambda *args: -1)
        with patch('faultlens._atop_exec.ctypes.CDLL', return_value=library), patch(
                'faultlens._atop_exec.os.execve', side_effect=AssertionError('must not exec')):
            self.assertEqual(125, _atop_exec.main(['/usr/bin/atop', '3', '20260101000000', '20260101000100']))

    def test_parent_stops_only_after_a_complete_validated_window(self):
        text = sample()
        self.assertIsNone(window_boundary(bytearray(text.encode()), EPOCH + 60))
        self.assertEqual(len(text), window_boundary(bytearray((text + 'partial').encode()), EPOCH + 30))
        self.assertIsNone(window_boundary(bytearray(b'partial'), EPOCH + 30))
        with self.assertRaises(ValueError):
            window_boundary(bytearray(b'not-a-resource-record\nSEP\n'), EPOCH)
        script = 'import sys,time; sys.stdout.write(' + repr(text) + '); sys.stdout.flush(); time.sleep(10)'
        result = _capture([sys.executable, '-c', script],
                          end_when=lambda output: window_boundary(output, EPOCH + 30))
        self.assertEqual('window_complete', result.state)
        self.assertIsNone(result.returncode)
        self.assertEqual(text, result.stdout)

    def test_helper_limits_and_no_new_privileges_apply_only_in_a_child(self):
        root = str(Path(__file__).resolve().parents[1])
        script = '''import sys,json,resource,ctypes
sys.path.insert(0, sys.argv[1])
from faultlens import _atop_exec as helper
def inspect(executable, arguments, environment):
 print(json.dumps({'as':resource.getrlimit(resource.RLIMIT_AS)[0], 'cpu':resource.getrlimit(resource.RLIMIT_CPU)[0], 'file':resource.getrlimit(resource.RLIMIT_FSIZE)[0], 'core':resource.getrlimit(resource.RLIMIT_CORE)[0], 'nnp':ctypes.CDLL(None).prctl(39,0,0,0,0), 'labels':arguments[4], 'end_flag': '-e' in arguments, 'home':environment['HOME'], 'tz':environment['TZ']}))
 raise SystemExit(0)
helper.os.execve=inspect
helper.main(['/usr/bin/atop',sys.argv[2],'20260101000000','20260101000100'])
'''
        parent_limit = resource.getrlimit(resource.RLIMIT_AS)
        with tempfile.TemporaryFile() as file:
            result = subprocess.run([sys.executable, '-I', '-c', script, root, str(file.fileno())],
                                    pass_fds=(file.fileno(),), capture_output=True, text=True, timeout=5, check=True)
        value = json.loads(result.stdout)
        self.assertEqual(64 * 1024 * 1024, value['as'])
        self.assertEqual(2, value['cpu'])
        self.assertEqual(0, value['file'])
        self.assertEqual(0, value['core'])
        self.assertEqual(1, value['nnp'])
        self.assertEqual('CPU,MEM,SWP', value['labels'])
        self.assertFalse(value['end_flag'])
        self.assertEqual('UTC', value['tz'])
        self.assertEqual('/nonexistent', value['home'])
        self.assertEqual(parent_limit, resource.getrlimit(resource.RLIMIT_AS))
