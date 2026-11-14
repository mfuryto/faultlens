"""Synthetic bounded receipt ranges; no real clock or journal changes."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import CommandRunner, Result
from faultlens.incidents import diagnose
from faultlens.journal import MAX_REALTIME_US
from tests.test_incidents import BOOT, record
from tests.test_event_search import candidate
from tests.test_journal_window import WindowRunner


class RangeRunner(WindowRunner):
    def __init__(self, records=(), **kwargs):
        super().__init__(records, **kwargs)
        self.ranges = []

    def read_boot_window(self, boot_id, since_us, *, until_us=None, system=False):
        self.ranges.append((boot_id, since_us, until_us, system))
        return self.result


class JournalRangeTests(unittest.TestCase):
    def test_range_boundaries_are_inclusive_and_keep_id_scope(self):
        runner = RangeRunner([record(realtime=1000), record(realtime=2000, monotonic=200)])
        data = diagnose(runner, boot_id=BOOT, since_us=1000, until_us=2000, system_journal=True)
        self.assertEqual([(BOOT, 1000, 2000, True)], runner.ranges)
        self.assertEqual([], runner.windows)
        self.assertEqual([], runner.requested)
        self.assertEqual('bounded_realtime_range', data['journal_window']['mode'])
        self.assertEqual(1000, data['journal_window']['since_realtime_us'])
        self.assertEqual(2, data['records_examined'])

    def test_start_only_equal_bounds_and_zero_are_distinct_from_default(self):
        for start, end in ((0, None), (0, 0), (1000, 1000), (MAX_REALTIME_US, MAX_REALTIME_US)):
            data = diagnose(RangeRunner([record(realtime=start)]), since_us=start, until_us=end)
            self.assertEqual('available', data['state'])
            self.assertEqual('tail_since_realtime' if end is None else 'bounded_realtime_range', data['journal_window']['mode'])

    def test_records_outside_either_boundary_reject_response_including_sentinel(self):
        for records in ([record(realtime=999)], [record(realtime=2001)],
                        [record(realtime=999, monotonic=0)] + [record(realtime=1500, monotonic=i+1) for i in range(500)]):
            data = diagnose(RangeRunner(records), since_us=1000, until_us=2000)
            self.assertEqual('invalid', data['journal_collection']['parse_state'])
            self.assertEqual([], data['findings'])

    def test_failed_or_empty_range_does_not_retry_broader_window(self):
        for result in (Result('timeout'), Result('output_limit'), Result('completed', '', 0), Result('completed', 'private error', 1)):
            runner = RangeRunner()
            runner.result = result
            data = diagnose(runner, since_us=1000, until_us=2000)
            self.assertEqual('unavailable', data['state'])
            self.assertEqual([], runner.windows)
            self.assertEqual([], runner.requested)
            self.assertNotIn('private error', json.dumps(data))

    def test_record_limit_does_not_imply_full_requested_range(self):
        data = diagnose(RangeRunner([record(realtime=1000+i, monotonic=i) for i in range(501)]), since_us=1000, until_us=2000)
        self.assertTrue(data['record_limit_reached'])
        self.assertEqual(1001, data['reconstruction']['first_record']['realtime_us'])
        self.assertEqual('unknown', data['journal_window']['completeness'])

    def test_targeted_queries_keep_independent_scope(self):
        runner = RangeRunner([record(realtime=1500)], kernel=[candidate(realtime=500), candidate(realtime=2500, monotonic=200)])
        data = diagnose(runner, since_us=1000, until_us=2000, search_events=True)
        self.assertEqual(2, data['event_search']['queries'][0]['candidates_examined'])
        self.assertEqual(1, data['records_examined'])

    def test_reversed_or_invalid_bounds_fail_before_command_execution(self):
        runner = RangeRunner()
        for start, end in ((2000, 1000), (-1, None), (True, 2000), ('1000', 2000), (MAX_REALTIME_US+1, None)):
            with self.assertRaises(ValueError):
                diagnose(runner, since_us=start, until_us=end)
            with patch('faultlens.commands._capture', side_effect=AssertionError('must not execute')):
                with self.assertRaises(ValueError):
                    CommandRunner().read_boot_window(BOOT, start, until_us=end)
        self.assertEqual([], runner.ranges)

    def test_cli_validates_scope_formats_and_order(self):
        for args in (['history', '--since-us', '1000'], ['check', '--since-us', '1000'],
                     ['diagnose', '--since-us', '-1'], ['diagnose', '--since-us', '1000;unsafe'],
                     ['diagnose', '--since-us', '2000', '--until-us', '1000']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)
        output = io.StringIO()
        main(['diagnose', '--since-us', '1000', '--until-us', '2000', '--json'],
             runner=RangeRunner([record(realtime=1500)]), stdout=output)
        self.assertEqual('bounded_realtime_range', json.loads(output.getvalue())['journal_window']['mode'])

    def test_native_arguments_are_exact_not_float_or_relative(self):
        with patch('faultlens.commands.trusted_tool', return_value='/usr/bin/journalctl'), patch(
                'faultlens.commands._capture', return_value=Result('completed', '', 0)) as capture:
            CommandRunner().read_boot_window(BOOT, 1767225600123456, until_us=1767225600654321, system=True)
        args = capture.call_args.args[0]
        self.assertIn('--since=@1767225600.123456', args)
        self.assertIn('--until=@1767225600.654321', args)
        self.assertIn('--system', args)
        self.assertIn('--lines=501', args)
