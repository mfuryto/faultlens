"""Synthetic multi-boot integration; no real journal, reboots or private fixtures."""
import contextlib
import io
import json
import unittest

from faultlens.cli import main
from faultlens.commands import Command, Result
from faultlens.journal import SHUTDOWN_REQUEST
from faultlens.overview import incidents
from tests.test_incidents import record

IDS = [format(index + 1, '032x') for index in range(9)]


class OverviewRunner:
    def __init__(self, count=5):
        self.listing = Result('completed', '\n'.join(
            f'{-index} {identity} synthetic' for index, identity in enumerate(IDS[:count])), 0)
        self.calls, self.reads = [], []
        self.results = {}
        for identity in IDS:
            rows = [record('Out of memory: Killed process 42', _BOOT_ID=identity)]
            self.results[identity] = Result('completed', '\n'.join(json.dumps(row) for row in rows), 0)

    def run(self, command):
        self.calls.append(command)
        if len(self.calls) > 1:
            raise AssertionError('Listing must be collected only once')
        return self.listing

    def read_boot(self, identity):
        self.reads.append(('visible', identity))
        return self.results[identity]

    def read_system_boot(self, identity):
        self.reads.append(('system', identity))
        return self.results[identity]


class IncidentOverviewTests(unittest.TestCase):
    def test_default_selects_three_previous_boots_from_one_listing(self):
        runner = OverviewRunner()
        data = incidents(runner)
        self.assertEqual('available', data['state'])
        self.assertEqual([Command.JOURNAL_BOOTS], runner.calls)
        self.assertEqual([('visible', value) for value in IDS[1:4]], runner.reads)
        self.assertTrue(data['selection_limit_reached'])
        self.assertEqual(3, data['selected_boot_count'])
        self.assertTrue(all(value['finding_counts_by_rule'] == {'kernel.oom': 1} for value in data['summaries']))

    def test_explicit_current_inclusion_and_system_scope(self):
        runner = OverviewRunner()
        data = incidents(runner, boot_count=2, include_current=True, system_journal=True)
        self.assertEqual([Command.JOURNAL_SYSTEM_BOOTS], runner.calls)
        self.assertEqual([('system', value) for value in IDS[:2]], runner.reads)
        self.assertEqual([0, -1], [value['boot']['index'] for value in data['summaries']])

    def test_current_only_listing_never_falls_back_without_opt_in(self):
        runner = OverviewRunner(count=1)
        data = incidents(runner)
        self.assertEqual('unavailable', data['state'])
        self.assertEqual('no_selected_boots_visible', data['reason'])
        self.assertEqual([], runner.reads)
        self.assertEqual([], data['summaries'])

    def test_listing_failures_and_malformed_scope_do_not_collect_tails(self):
        for result in (Result('timeout'), Result('completed', '', 1),
                       Result('completed', 'private-host error', 0), Result('completed', '', 0)):
            runner = OverviewRunner()
            runner.listing = result
            data = incidents(runner)
            self.assertEqual('unavailable', data['state'])
            self.assertEqual([], runner.reads)
            self.assertNotIn('private-host', json.dumps(data))

    def test_independent_failures_do_not_replace_a_missing_boot(self):
        for failure in (Result('timeout'), Result('completed', '', 0), Result('output_limit'),
                        Result('completed', json.dumps(record(_BOOT_ID=IDS[0])), 0)):
            runner = OverviewRunner()
            runner.results[IDS[2]] = failure
            data = incidents(runner)
            self.assertEqual('partial', data['state'])
            self.assertEqual(['available', 'unavailable', 'available'], [value['state'] for value in data['summaries']])
            self.assertEqual([('visible', value) for value in IDS[1:4]], runner.reads)
            self.assertIsNone(data['summaries'][1]['last_record'])

    def test_all_failed_tails_are_unavailable_not_healthy(self):
        runner = OverviewRunner()
        runner.results = dict.fromkeys(IDS, Result('completed', '', 1))
        self.assertEqual('unavailable', incidents(runner)['state'])

    def test_caps_shutdown_uncertainty_and_redaction_survive_summary(self):
        runner = OverviewRunner(count=2)
        rows = [record('private-unit message', _BOOT_ID=IDS[1], monotonic=index,
                       _TRANSPORT='journal', _PID='1', _COMM='systemd', MESSAGE_ID=SHUTDOWN_REQUEST)
                for index in range(501)]
        runner.results[IDS[1]] = Result('completed', '\n'.join(map(json.dumps, rows)), 0)
        data = incidents(runner)
        summary, = data['summaries']
        self.assertEqual(500, summary['records_examined'])
        self.assertEqual(500, summary['finding_count'])
        self.assertTrue(summary['record_limit_reached'])
        self.assertEqual('Marker observed; completion unknown', summary['shutdown_assessment'])
        self.assertEqual('Unknown', summary['root_cause'])
        self.assertEqual('unknown', summary['completeness'])
        self.assertNotIn('private-unit', json.dumps(data))
        self.assertNotIn('findings', summary)

    def test_seven_boot_limit_and_sparse_indices(self):
        runner = OverviewRunner(count=9)
        data = incidents(runner, boot_count=7)
        self.assertEqual(7, len(runner.reads))
        self.assertTrue(data['selection_limit_reached'])
        runner = OverviewRunner(count=2)
        runner.listing = Result('completed', f'-8 {IDS[2]} synthetic\n-3 {IDS[1]} synthetic', 0)
        self.assertEqual([-3, -8], [value['boot']['index'] for value in incidents(runner)['summaries']])

    def test_invalid_api_arguments_fail_before_execution(self):
        runner = OverviewRunner()
        for kwargs in ({'boot_count': True}, {'boot_count': 0}, {'boot_count': 8}, {'boot_count': '3'},
                       {'system_journal': 1}, {'include_current': 'yes'}):
            with self.assertRaises(ValueError):
                incidents(runner, **kwargs)
        self.assertEqual([], runner.calls)

    def test_cli_rejects_overview_flags_elsewhere_and_single_boot_sources(self):
        for args in (['history', '--boot-count', '3'], ['diagnose', '--include-current'],
                     ['incidents', '--boot-count', '8'], ['incidents', '--boot-count', '0'],
                     ['incidents', '--boot-count', '３'], ['incidents', '--atop-date', '20260101'],
                     ['incidents', '--boot', '-1'], ['incidents', '--search-events'],
                     ['incidents', '--since-us', '0'], ['incidents', '--pstore']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)

    def test_cli_json_and_text_present_read_only_scope_and_followup(self):
        for flags in ([], ['--json']):
            output = io.StringIO()
            self.assertEqual(0, main(['incidents', '--system-journal', '--boot-count', '1'] + flags,
                                    runner=OverviewRunner(), stdout=output))
            if flags:
                data = json.loads(output.getvalue())
                self.assertEqual('incidents', data['command'])
                self.assertEqual('system', data['journal_scope']['requested'])
            else:
                self.assertIn('diagnose --boot-id ' + IDS[1] + ' --system-journal --json', output.getvalue())
                self.assertIn('root cause Unknown', output.getvalue())
