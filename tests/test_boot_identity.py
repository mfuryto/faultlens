"""Stable boot selection using invented scoped listings only."""
import contextlib
import io
import json
import unittest

from faultlens.cli import main
from faultlens.commands import Result
from faultlens.incidents import diagnose
from tests.test_event_search import SearchRunner, candidate
from tests.test_incidents import BOOT, CURRENT, JournalRunner, record
from tests.test_journal_scope import ScopedRunner


class BootIdentityTests(unittest.TestCase):
    def test_exact_id_survives_relative_index_changes(self):
        for index in (0, -1, -2):
            runner = JournalRunner([record()])
            runner.boot_result = Result('completed', str(index) + ' ' + BOOT + ' synthetic\n', 0)
            data = diagnose(runner, boot_id=BOOT)
            self.assertEqual([BOOT], runner.requested)
            self.assertEqual(BOOT, data['selected_boot']['boot_id'])
            self.assertEqual(index, data['selected_boot']['index'])
            self.assertEqual({'method': 'id', 'requested': BOOT, 'state': 'resolved'}, data['boot_selection'])

    def test_default_and_explicit_index_keep_previous_selection_behavior(self):
        for arguments in ({}, {'boot_index': -1}):
            runner = JournalRunner([record()])
            data = diagnose(runner, **arguments)
            self.assertEqual([BOOT], runner.requested)
            self.assertEqual({'method': 'index', 'requested': -1, 'state': 'resolved'}, data['boot_selection'])

    def test_unknown_id_never_queries_directly_or_falls_back(self):
        runner = SearchRunner([record()], kernel=[candidate()])
        data = diagnose(runner, boot_id='c' * 32, search_events=True)
        self.assertEqual('not_visible', data['boot_selection']['state'])
        self.assertEqual([], runner.requested)
        self.assertEqual([], runner.searches)
        self.assertIsNone(data['selected_boot'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertEqual('unavailable', data['state'])

    def test_failed_or_invalid_listing_prevents_id_query(self):
        for result in (Result('timeout'), Result('completed', '', 1), Result('completed', '', 0),
                       Result('completed', 'malformed', 0)):
            runner = JournalRunner([record()])
            runner.boot_result = result
            data = diagnose(runner, boot_id=BOOT)
            self.assertEqual('listing_unavailable', data['boot_selection']['state'])
            self.assertEqual([], runner.requested)
            self.assertIsNone(data['journal_collection'])

    def test_id_must_be_visible_in_requested_system_scope(self):
        runner = ScopedRunner([record()])
        runner.system_boot_result = Result('completed', '0 ' + CURRENT + ' synthetic\n', 0)
        data = diagnose(runner, boot_id=BOOT, system_journal=True)
        self.assertEqual('not_visible', data['boot_selection']['state'])
        self.assertEqual([], runner.system_requested)
        self.assertEqual([], runner.requested)
        runner.system_boot_result = Result('completed', '-2 ' + BOOT + ' synthetic\n', 0)
        data = diagnose(runner, boot_id=BOOT, system_journal=True)
        self.assertEqual([BOOT], runner.system_requested)
        self.assertEqual(-2, data['selected_boot']['index'])

    def test_targeted_queries_and_tail_use_same_selected_identity(self):
        runner = SearchRunner([record()], kernel=[candidate()])
        data = diagnose(runner, boot_id=BOOT, system_journal=True, search_events=True)
        self.assertEqual([BOOT], runner.requested)
        self.assertEqual([(BOOT, 'kernel_warnings', True), (BOOT, 'systemd_events', True)], runner.searches)
        self.assertEqual(BOOT, data['event_search']['boot_id'])

    def test_mixed_boot_response_is_rejected_after_identity_resolution(self):
        runner = JournalRunner([record(_BOOT_ID=CURRENT)])
        data = diagnose(runner, boot_id=BOOT)
        self.assertEqual('resolved', data['boot_selection']['state'])
        self.assertEqual('invalid', data['journal_collection']['parse_state'])
        self.assertEqual('unavailable', data['state'])
        self.assertEqual([], data['findings'])

    def test_bad_ids_and_conflicting_api_selectors_fail_before_collection(self):
        runner = SearchRunner()
        for value in ('../private', BOOT + ';unsafe', BOOT.upper(), 'a' * 31, 'a' * 33,
                      'g' * 32, 'a' * 32 + '\n', 42, False):
            with self.assertRaises(ValueError):
                diagnose(runner, boot_id=value)
        for index in (0, -1, -2):
            with self.assertRaises(ValueError):
                diagnose(runner, index, boot_id=BOOT)
        self.assertEqual([], runner.requested)
        self.assertEqual([], runner.searches)

    def test_cli_validates_ids_command_scope_and_mutual_exclusion(self):
        invalid = [['diagnose', '--boot-id', '../private'], ['diagnose', '--boot-id', BOOT.upper()],
                   ['diagnose', '--boot-id', BOOT, '--boot', '0'],
                   ['diagnose', '--boot-id', BOOT, '--previous-boot']]
        invalid += [[command, '--boot-id', BOOT] for command in ('status', 'check', 'history')]
        for arguments in invalid:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(arguments)
        for json_mode in (True, False):
            output = io.StringIO()
            runner = JournalRunner([record()])
            main(['diagnose', '--boot-id', BOOT] + (['--json'] if json_mode else []), runner=runner, stdout=output)
            self.assertEqual([BOOT], runner.requested)
            if json_mode:
                self.assertEqual('id', json.loads(output.getvalue())['boot_selection']['method'])
            else:
                self.assertIn('Boot selection:', output.getvalue())
