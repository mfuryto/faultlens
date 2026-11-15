"""Synthetic retained-window reconstruction; no real incident data or clock changes."""
import io
import json
import unittest

from faultlens.cli import main
from faultlens.commands import Result
from faultlens.incidents import SHUTDOWN_REQUEST, diagnose
from faultlens.journal import CLOCK_MAPPING_TOLERANCE_US
from tests.test_incidents import BOOT, JournalRunner, record
from tests.test_atop import AtopRunner, EPOCH


class ReconstructionTests(unittest.TestCase):
    def test_observed_window_and_finding_positions_use_retained_monotonic_times(self):
        data = diagnose(JournalRunner([
            record(monotonic=10, realtime=100),
            record('Kernel panic - not syncing: synthetic', monotonic=40, realtime=130),
            record(monotonic=100, realtime=190)]))
        context = data['reconstruction']
        self.assertEqual('available', context['state'])
        self.assertEqual(90, context['monotonic_span_us'])
        self.assertEqual(10, context['first_record']['monotonic_us'])
        self.assertEqual(data['last_record'], context['last_record'])
        self.assertEqual(60, context['largest_observed_record_interval']['duration_us'])
        self.assertEqual(1, context['finding_count'])
        self.assertEqual({'kernel.panic': 1}, context['finding_counts_by_rule'])
        point, = data['timeline']
        self.assertEqual(0, point['finding_index'])
        self.assertEqual(30, point['from_first_visible_record_us'])
        self.assertEqual(60, point['before_last_visible_record_us'])
        self.assertIsNone(point['since_previous_finding_us'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertEqual('Unknown', data['shutdown_assessment'])

    def test_equal_timestamps_and_repeated_reports_have_no_inferred_causal_order(self):
        data = diagnose(JournalRunner([
            record('Kernel panic - not syncing: synthetic one', monotonic=10, realtime=100),
            record('Kernel panic - not syncing: synthetic two', monotonic=10, realtime=100),
            record('Kernel panic - not syncing: synthetic three', monotonic=25, realtime=115)]))
        self.assertEqual(1, data['reconstruction']['equal_monotonic_record_pairs'])
        self.assertEqual(3, data['reconstruction']['finding_count'])
        self.assertEqual(0, data['timeline'][1]['since_previous_finding_us'])
        self.assertEqual('unresolved_equal_timestamp', data['timeline'][1]['relative_order'])
        self.assertEqual(15, data['timeline'][2]['since_previous_finding_us'])
        self.assertIn('not independent incidents', ' '.join(data['reconstruction']['limitations']))

    def test_equal_monotonic_wall_difference_is_not_labeled_a_proven_regression(self):
        data = diagnose(JournalRunner([record(monotonic=10, realtime=9000000),
                                      record(monotonic=10, realtime=1000000)]))
        clock = data['reconstruction']['clock_mapping']
        self.assertEqual(0, clock['wall_clock_regression_count'])
        self.assertEqual(1, clock['equal_timestamp_wall_clock_difference_pairs'])
        self.assertEqual('unresolved_equal_timestamp', clock['change_examples'][0]['relative_order'])
        self.assertEqual('variable', clock['assessment'])

    def test_reversed_wall_clock_preserves_boot_local_order_and_exposes_mapping(self):
        data = diagnose(JournalRunner([record(monotonic=100, realtime=9000000),
                                      record(monotonic=300, realtime=1000000)]))
        clock = data['reconstruction']['clock_mapping']
        self.assertEqual(200, data['reconstruction']['monotonic_span_us'])
        self.assertEqual('variable', clock['assessment'])
        self.assertEqual(1, clock['wall_clock_regression_count'])
        self.assertEqual(1, clock['significant_adjacent_change_count'])
        self.assertEqual(-8000200, clock['change_examples'][0]['offset_change_us'])

    def test_global_offset_range_detects_gradual_variation_and_tolerance_is_inclusive(self):
        for extra, assessment in ((0, 'within_tolerance'), (1, 'variable')):
            data = diagnose(JournalRunner([record(monotonic=0, realtime=10000000),
                                          record(monotonic=10, realtime=10000010 + CLOCK_MAPPING_TOLERANCE_US + extra)]))
            self.assertEqual(assessment, data['reconstruction']['clock_mapping']['assessment'])
        data = diagnose(JournalRunner([record(monotonic=index, realtime=10000000 + index + index * 1000000)
                                       for index in range(4)]))
        clock = data['reconstruction']['clock_mapping']
        self.assertEqual('variable', clock['assessment'])
        self.assertEqual(0, clock['significant_adjacent_change_count'])
        self.assertEqual([], clock['change_examples'])

    def test_atop_gate_and_reconstruction_share_the_clock_tolerance(self):
        for extra, expected in ((0, 'within_tolerance'), (1, 'variable')):
            runner = AtopRunner(records=[record(monotonic=15000000, realtime=(EPOCH + 15) * 1000000),
                                         record(monotonic=20000000, realtime=(EPOCH + 20) * 1000000 + CLOCK_MAPPING_TOLERANCE_US + extra)])
            data = diagnose(runner, atop_date='20260101')
            self.assertEqual(expected, data['reconstruction']['clock_mapping']['assessment'])
            if extra:
                self.assertEqual('ambiguous_journal_clock_mapping', data['atop']['reason'])
                self.assertEqual([], runner.atop_calls)
            else:
                self.assertEqual('available', data['atop']['state'])

    def test_clock_examples_are_bounded_without_hiding_total_changes(self):
        data = diagnose(JournalRunner([record(monotonic=index, realtime=10000000 + index + (index % 2) * 3000000)
                                       for index in range(500)]))
        clock = data['reconstruction']['clock_mapping']
        self.assertEqual(499, clock['significant_adjacent_change_count'])
        self.assertEqual(16, len(clock['change_examples']))
        self.assertTrue(clock['change_examples_truncated'])

    def test_long_silent_interval_is_not_classified_as_missing_logs_or_shutdown(self):
        data = diagnose(JournalRunner([record(monotonic=0), record(monotonic=10**19)]))
        context = data['reconstruction']
        self.assertEqual(10**19, context['largest_observed_record_interval']['duration_us'])
        self.assertEqual([], data['findings'])
        self.assertEqual('Unknown', data['shutdown_assessment'])
        self.assertIn('do not prove lost logging', ' '.join(context['limitations']))

    def test_cap_and_unsupported_messages_are_not_misrepresented_as_full_boot_coverage(self):
        data = diagnose(JournalRunner([record(message=[1, 2], monotonic=index) for index in range(501)]))
        context = data['reconstruction']
        self.assertEqual(500, context['record_count'])
        self.assertEqual(1, context['first_record']['monotonic_us'])
        self.assertEqual(499, context['monotonic_span_us'])
        self.assertTrue(context['record_limit_reached'])
        self.assertEqual(501, context['unsupported_messages_in_collected_response'])
        self.assertEqual({}, context['finding_counts_by_rule'])

    def test_single_empty_and_failed_sources_preserve_unavailable_semantics(self):
        data = diagnose(JournalRunner([record()]))
        context = data['reconstruction']
        self.assertEqual(0, context['monotonic_span_us'])
        self.assertIsNone(context['largest_observed_record_interval'])
        self.assertEqual('unavailable', diagnose(JournalRunner())['reconstruction']['state'])
        runner = JournalRunner()
        runner.result = Result('timeout')
        self.assertIsNone(diagnose(runner)['reconstruction'])
        runner.result = Result('completed', 'malformed', 0)
        self.assertIsNone(diagnose(runner)['reconstruction'])
        self.assertIsNone(diagnose(JournalRunner(), -128)['reconstruction'])

    def test_raw_message_cursor_and_host_metadata_are_not_copied_to_summary(self):
        marker = 'synthetic-private-payload'
        runner = JournalRunner([record('Kernel panic - not syncing: ' + marker,
                                       __CURSOR='s=' + marker, _HOSTNAME=marker, _COMM=marker)])
        for json_mode in (True, False):
            output = io.StringIO()
            main(['diagnose'] + (['--json'] if json_mode else ['--details']), runner=runner, stdout=output)
            self.assertNotIn(marker, output.getvalue())
            self.assertNotIn('s=' + marker, output.getvalue())
            if not json_mode:
                self.assertIn('Observed journal span:', output.getvalue())
                self.assertIn('Journal position:', output.getvalue())

    def test_shutdown_marker_and_report_order_remain_observations_only(self):
        data = diagnose(JournalRunner([
            record(_PID='1', _COMM='systemd', MESSAGE_ID=SHUTDOWN_REQUEST, monotonic=10),
            record('Kernel panic - not syncing: synthetic', monotonic=20)]))
        self.assertEqual('Marker observed; completion unknown', data['shutdown_assessment'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertEqual(10, data['timeline'][1]['since_previous_finding_us'])
        self.assertEqual(BOOT, data['reconstruction']['first_record']['boot_id'])
