"""Invented filtered boot candidates; no actual incidents or host journals in CI."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import Command, CommandRunner, Result
from faultlens.incidents import SHUTDOWN_REQUEST, UNIT_START_FAILED, diagnose
from tests.test_incidents import BOOT, CURRENT, JournalRunner, listing, record
from tests.test_atop import sample, EPOCH


class SearchRunner(JournalRunner):
    def __init__(self, records=(), kernel=(), systemd=()):
        super().__init__(records)
        self.candidates = {'kernel_warnings': Result('completed', listing(kernel), 0),
                           'systemd_events': Result('completed', listing(systemd), 0)}
        self.searches = []

    def run(self, command):
        assert command in {Command.JOURNAL_BOOTS, Command.JOURNAL_SYSTEM_BOOTS}
        return self.boot_result

    def read_event_candidates(self, boot_id, query, *, system=False):
        self.searches.append((boot_id, query, system))
        return self.candidates[query]

    def read_system_boot(self, boot_id):
        return self.read_boot(boot_id)


def candidate(message='Kernel panic - not syncing: synthetic', **fields):
    return record(message, PRIORITY='3', **fields)


def systemd_candidate(**fields):
    return record(_PID='1', _COMM='systemd', _TRANSPORT='journal', MESSAGE_ID=SHUTDOWN_REQUEST, **fields)


class EventSearchTests(unittest.TestCase):
    def test_default_diagnosis_never_searches(self):
        runner = SearchRunner([record()])
        data = diagnose(runner)
        self.assertEqual([], runner.searches)
        self.assertNotIn('event_search', data)

    def test_search_finds_older_supported_events_without_relabeling_tail_coverage(self):
        runner = SearchRunner([record(monotonic=10000)], kernel=[candidate(monotonic=10)],
                              systemd=[systemd_candidate(monotonic=20)])
        data = diagnose(runner, search_events=True)
        search = data['event_search']
        self.assertEqual('available', search['state'])
        self.assertEqual('unknown', search['completeness'])
        self.assertEqual([], data['findings'])
        self.assertEqual(10000, data['reconstruction']['first_record']['monotonic_us'])
        self.assertEqual('kernel.panic', search['queries'][0]['findings'][0]['rule_id'])
        self.assertEqual('systemd.shutdown_marker', search['queries'][1]['findings'][0]['rule_id'])
        self.assertEqual(10, search['queries'][0]['candidate_window']['first_candidate']['monotonic_us'])
        self.assertEqual('Unknown', data['shutdown_assessment'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertEqual([(BOOT, 'kernel_warnings', False), (BOOT, 'systemd_events', False)], runner.searches)

    def test_system_scope_is_propagated_to_both_queries_without_reselecting_boot(self):
        data_runner = SearchRunner([record()], kernel=[candidate()])
        diagnose(data_runner, system_journal=True, search_events=True)
        self.assertEqual([(BOOT, 'kernel_warnings', True), (BOOT, 'systemd_events', True)], data_runner.searches)
        self.assertEqual([BOOT], data_runner.requested)

    def test_unresolved_boot_never_triggers_search_or_scope_fallback(self):
        for failure in ('missing_boot', 'listing_failure'):
            runner = SearchRunner([record()])
            if failure == 'listing_failure':
                runner.boot_result = Result('completed', '', 1)
            data = diagnose(runner, -128, search_events=True)
            self.assertEqual([], runner.searches)
            self.assertEqual('boot_scope_unresolved', data['event_search']['reason'])
            self.assertEqual([], runner.requested)

    def test_queries_are_independent_of_tail_failure_and_each_other(self):
        runner = SearchRunner(kernel=[candidate()])
        runner.result = Result('output_limit')
        runner.candidates['systemd_events'] = Result('timeout')
        data = diagnose(runner, search_events=True)
        self.assertEqual('unavailable', data['state'])
        self.assertEqual('partial', data['event_search']['state'])
        self.assertEqual('kernel.panic', data['event_search']['queries'][0]['findings'][0]['rule_id'])
        self.assertEqual('not_attempted', data['event_search']['queries'][1]['parse_state'])
        self.assertIsNone(data['reconstruction'])

    def test_failed_and_malformed_queries_discard_results_without_parsing_error_text(self):
        for result in (Result('missing'), Result('timeout'), Result('output_limit'),
                       Result('completed', 'synthetic-private-error', 1), Result('completed', 'malformed', 0)):
            runner = SearchRunner([record()])
            runner.candidates = {query: result for query in runner.candidates}
            data = diagnose(runner, search_events=True)
            self.assertEqual('unavailable', data['event_search']['state'])
            self.assertNotIn('synthetic-private-error', json.dumps(data))
            self.assertTrue(all(not query['findings'] for query in data['event_search']['queries']))
            self.assertEqual('available', data['state'])

    def test_successful_empty_queries_are_available_without_absence_claims(self):
        data = diagnose(SearchRunner([record()]), search_events=True)
        for query in data['event_search']['queries']:
            self.assertEqual('available', query['state'])
            self.assertEqual('empty', query['parse_state'])
            self.assertEqual('no_candidates_returned', query['reason'])
        self.assertIn('does not prove no earlier events', ' '.join(data['event_search']['limitations']))

    def test_candidate_filters_are_revalidated_including_omitted_sentinel(self):
        invalid = [candidate(_TRANSPORT='stdout'), record(PRIORITY='6'),
                   record('Kernel panic - not syncing: synthetic'), candidate(_BOOT_ID=CURRENT),
                   record(PRIORITY=['3']), record(PRIORITY='NaN')]
        for value in invalid:
            runner = SearchRunner([record()], kernel=[value])
            query = diagnose(runner, search_events=True)['event_search']['queries'][0]
            self.assertEqual('invalid', query['parse_state'])
            self.assertEqual([], query['findings'])
        values = [record(PRIORITY='6', monotonic=0)] + [candidate(monotonic=index+1) for index in range(500)]
        runner = SearchRunner([record()], kernel=values)
        self.assertEqual('invalid', diagnose(runner, search_events=True)['event_search']['queries'][0]['parse_state'])
        for fields in ({'_PID': '42', '_COMM': 'systemd', 'MESSAGE_ID': SHUTDOWN_REQUEST},
                       {'_PID': '1', '_COMM': 'application', 'MESSAGE_ID': SHUTDOWN_REQUEST},
                       {'_PID': '1', '_COMM': 'systemd', 'MESSAGE_ID': 'a' * 32}):
            runner = SearchRunner([record()], systemd=[record(**fields)])
            self.assertEqual('invalid', diagnose(runner, search_events=True)['event_search']['queries'][1]['parse_state'])

    def test_caps_apply_separately_and_noise_is_not_classified_as_supported_event(self):
        runner = SearchRunner([record()], kernel=[candidate(monotonic=index) for index in range(501)],
                              systemd=[systemd_candidate(monotonic=index) for index in range(501)])
        data = diagnose(runner, search_events=True)
        for query in data['event_search']['queries']:
            self.assertEqual(500, query['candidates_examined'])
            self.assertTrue(query['record_limit_reached'])
            self.assertEqual(500, len(query['findings']))
        runner = SearchRunner([record()], kernel=[candidate('Other synthetic kernel warning')])
        query = diagnose(runner, search_events=True)['event_search']['queries'][0]
        self.assertEqual(1, query['candidates_examined'])
        self.assertEqual([], query['findings'])

    def test_reverse_response_and_both_systemd_ids_preserve_filtered_chronology(self):
        runner = SearchRunner([record()], kernel=[candidate(monotonic=index) for index in reversed(range(501))],
                              systemd=[systemd_candidate(monotonic=20),
                                       record(_PID='1', _COMM='systemd', MESSAGE_ID=UNIT_START_FAILED, monotonic=10)])
        search = diagnose(runner, search_events=True)['event_search']
        self.assertEqual(1, search['queries'][0]['candidate_window']['first_candidate']['monotonic_us'])
        self.assertEqual(500, search['queries'][0]['candidate_window']['last_candidate']['monotonic_us'])
        self.assertEqual(['systemd.start_job_failed', 'systemd.shutdown_marker'],
                         [item['rule_id'] for item in search['queries'][1]['timeline']])

    def test_repeated_views_are_not_merged_or_treated_as_independent_corroboration(self):
        value = candidate(__CURSOR='s=synthetic', monotonic=10)
        data = diagnose(SearchRunner([value], kernel=[value]), search_events=True)
        self.assertEqual(1, len(data['findings']))
        self.assertEqual(1, len(data['event_search']['queries'][0]['findings']))
        self.assertEqual('Unknown', data['root_cause'])
        self.assertIn('not independent corroboration', ' '.join(data['event_search']['limitations']))

    def test_targeted_findings_do_not_expand_atop_replay_or_pair_with_tail_samples(self):
        runner = SearchRunner([record(realtime=(EPOCH + 15) * 1000000, monotonic=15000000)],
                              kernel=[candidate(realtime=(EPOCH + 10) * 1000000, monotonic=10000000)])
        calls = []
        def read_atop(date, start, end):
            calls.append((date, start, end))
            return Result('completed', sample(), 0)
        runner.read_atop = read_atop
        data = diagnose(runner, atop_date='20260101', search_events=True)
        self.assertEqual(1, len(calls))
        self.assertEqual([], data['atop']['correlations'])
        self.assertEqual(1, len(data['event_search']['queries'][0]['findings']))

    def test_raw_fields_are_redacted_and_filtered_time_is_not_whole_boot_coverage(self):
        runner = SearchRunner([record()], kernel=[candidate('Kernel panic - not syncing: synthetic-private-payload',
                              __CURSOR='s=synthetic-private-payload', monotonic=10), candidate(monotonic=10000000)])
        for json_mode in (True, False):
            output = io.StringIO()
            main(['diagnose', '--search-events'] + (['--json'] if json_mode else []), runner=runner, stdout=output)
            self.assertNotIn('synthetic-private-payload', output.getvalue())
            self.assertIn('Targeted event search:' if not json_mode else 'candidate_window', output.getvalue())
        search = diagnose(runner, search_events=True)['event_search']
        self.assertNotIn('largest_observed_record_interval', json.dumps(search))
        self.assertIn('not log gaps', ' '.join(search['limitations']))

    def test_cli_and_api_reject_misplaced_or_untrusted_options_before_execution(self):
        for command in ('status', 'history', 'check'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([command, '--search-events'])
        runner = SearchRunner()
        for value in ('yes', 1, None):
            with self.assertRaises(ValueError):
                diagnose(runner, search_events=value)
        self.assertEqual([], runner.searches)
        with patch('faultlens.commands._capture', side_effect=AssertionError('must not execute')):
            for boot_id, query, system in (('../private', 'kernel_warnings', False), (BOOT, '--file=private', False),
                                            (BOOT, 'kernel_warnings', 'system')):
                with self.assertRaises(ValueError):
                    CommandRunner().read_event_candidates(boot_id, query, system=system)

    def test_fixed_native_arguments_have_no_regex_paths_or_unbounded_output(self):
        with patch('faultlens.commands.trusted_tool', return_value='/usr/bin/journalctl'), patch(
                'faultlens.commands._capture', return_value=Result('completed', '', 0)) as capture:
            runner = CommandRunner()
            runner.read_event_candidates(BOOT, 'kernel_warnings', system=True)
            kernel_args = capture.call_args.args[0]
            runner.read_event_candidates(BOOT, 'systemd_events')
            systemd_args = capture.call_args.args[0]
        self.assertIn('--system', kernel_args)
        self.assertNotIn('--system', systemd_args)
        self.assertIn('--priority=warning', kernel_args)
        self.assertIn('_TRANSPORT=kernel', kernel_args)
        self.assertIn('_PID=1', systemd_args)
        self.assertIn('_COMM=systemd', systemd_args)
        self.assertIn('MESSAGE_ID=' + SHUTDOWN_REQUEST, systemd_args)
        self.assertIn('MESSAGE_ID=' + UNIT_START_FAILED, systemd_args)
        for args in (kernel_args, systemd_args):
            self.assertIn('--boot=' + BOOT, args)
            self.assertIn('--lines=501', args)
            self.assertTrue(any('PRIORITY' in arg for arg in args if arg.startswith('--output-fields=')))
            self.assertFalse(any(arg.startswith(('--grep', '--file', '--directory', '--merge', '--since', '--until')) for arg in args))
