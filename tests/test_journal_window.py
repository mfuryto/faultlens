"""Synthetic historical receipt boundaries; never change the host clock or journal."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import CommandRunner, Result
from faultlens.incidents import diagnose
from faultlens.journal import MAX_REALTIME_US
from tests.test_incidents import BOOT, CURRENT, listing, record
from tests.test_event_search import SearchRunner, candidate
from tests.test_atop import EPOCH, sample


class WindowRunner(SearchRunner):
    def __init__(self, records=(), **kwargs):
        super().__init__(records, **kwargs)
        self.windows = []

    def read_boot_until(self, boot_id, until_us, *, system=False):
        self.windows.append((boot_id, until_us, system))
        return self.result


class JournalWindowTests(unittest.TestCase):
    def test_exact_id_scope_and_boundary_are_kept_without_latest_tail_fallback(self):
        runner = WindowRunner([record(realtime=900, monotonic=10)])
        data = diagnose(runner, boot_id=BOOT, system_journal=True, until_us=1000)
        self.assertEqual([(BOOT, 1000, True)], runner.windows)
        self.assertEqual([], runner.requested)
        self.assertEqual({'mode': 'tail_until_realtime', 'since_realtime_us': None, 'until_realtime_us': 1000, 'completeness': 'unknown'}, data['journal_window'])
        self.assertEqual('available', data['state'])
        self.assertEqual(900, data['last_record']['realtime_us'])
        self.assertEqual('Unknown', data['root_cause'])

    def test_default_does_not_request_a_historical_window(self):
        runner = WindowRunner([record()])
        data = diagnose(runner)
        self.assertEqual([], runner.windows)
        self.assertEqual([BOOT], runner.requested)
        self.assertEqual('tail', data['journal_window']['mode'])

    def test_boundary_is_inclusive_and_zero_is_not_treated_as_unspecified(self):
        for boundary in (0, 1000, MAX_REALTIME_US):
            runner = WindowRunner([record(realtime=boundary)])
            self.assertEqual('available', diagnose(runner, until_us=boundary)['state'])
            self.assertEqual([(BOOT, boundary, False)], runner.windows)

    def test_later_records_and_invalid_sentinel_reject_the_entire_response(self):
        for values in ([record(realtime=1001)],
                       [record(realtime=1001, monotonic=0)] + [record(realtime=900, monotonic=i+1) for i in range(500)],
                       [record(realtime=900, _BOOT_ID=CURRENT)]):
            data = diagnose(WindowRunner(values), until_us=1000)
            self.assertEqual('unavailable', data['state'])
            self.assertEqual('invalid', data['journal_collection']['parse_state'])
            self.assertEqual([], data['findings'])

    def test_failed_or_empty_historical_read_never_uses_latest_data(self):
        for result in (Result('timeout'), Result('output_limit'), Result('completed', 'private error', 1),
                       Result('completed', '', 0)):
            runner = WindowRunner([record()])
            runner.result = result
            data = diagnose(runner, until_us=1000)
            self.assertEqual('unavailable', data['state'])
            self.assertEqual([], runner.requested)
            self.assertNotIn('private error', json.dumps(data))

    def test_targeted_search_keeps_its_selected_boot_scope(self):
        runner = WindowRunner([record(realtime=900)], kernel=[candidate(realtime=2000)])
        data = diagnose(runner, until_us=1000, search_events=True)
        self.assertEqual(2000, data['event_search']['queries'][0]['candidate_window']['first_candidate']['realtime_us'])
        self.assertEqual(900, data['last_record']['realtime_us'])
        self.assertIn('whole-selected-boot scope', ' '.join(data['limitations']))

    def test_atop_anchors_to_last_returned_record_not_requested_cutoff(self):
        runner = WindowRunner([record(realtime=(EPOCH + 15) * 1000000, monotonic=15000000)])
        calls = []
        def read_atop(date, start, end):
            calls.append((start, end))
            return Result('completed', sample(), 0)
        runner.read_atop = read_atop
        data = diagnose(runner, until_us=(EPOCH + 1000) * 1000000, atop_date='20260101')
        self.assertEqual(EPOCH + 3615, calls[0][1])
        self.assertEqual('available', data['atop']['state'])

    def test_unresolved_boot_never_runs_a_historical_read(self):
        runner = WindowRunner([record(realtime=900)])
        data = diagnose(runner, boot_id='c' * 32, until_us=1000)
        self.assertEqual('not_visible', data['boot_selection']['state'])
        self.assertEqual([], runner.windows)

    def test_bad_boundaries_reject_before_any_command(self):
        runner = WindowRunner()
        for value in (-1, True, 1.5, '1000', MAX_REALTIME_US + 1):
            with self.assertRaises(ValueError):
                diagnose(runner, until_us=value)
            with patch('faultlens.commands._capture', side_effect=AssertionError('must not execute')):
                with self.assertRaises(ValueError):
                    CommandRunner().read_boot_until(BOOT, value)
        self.assertEqual([], runner.windows)

    def test_cli_rejects_bad_formats_and_wrong_commands(self):
        for value in ('-1', '+1', '1.5', 'NaN', '1e6', '1000;unsafe', '١٢', str(MAX_REALTIME_US+1)):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['diagnose', '--until-us', value])
        for command in ('status', 'history', 'check'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([command, '--until-us', '1000'])
        for json_mode in (True, False):
            output = io.StringIO()
            main(['diagnose', '--until-us', '1000'] + (['--json'] if json_mode else ['--details']),
                 runner=WindowRunner([record(realtime=900)]), stdout=output)
            self.assertIn('journal_window' if json_mode else 'Journal window:', output.getvalue())

    def test_native_boundary_format_is_exact_and_fixed(self):
        with patch('faultlens.commands.trusted_tool', return_value='/usr/bin/journalctl'), patch(
                'faultlens.commands._capture', return_value=Result('completed', '', 0)) as capture:
            CommandRunner().read_boot_until(BOOT, 1767225600123456, system=True)
        args = capture.call_args.args[0]
        self.assertIn('--until=@1767225600.123456', args)
        self.assertIn('--boot=' + BOOT, args)
        self.assertIn('--system', args)
        self.assertIn('--lines=501', args)
        self.assertNotIn('--follow', args)
