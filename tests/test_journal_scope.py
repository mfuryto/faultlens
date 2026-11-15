"""Synthetic journal source selection; no permission, group or service changes."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import Command, CommandRunner, Result
from faultlens.incidents import diagnose, history
from tests.test_incidents import BOOT, CURRENT, JournalRunner, record


class ScopedRunner(JournalRunner):
    def __init__(self, records=()):
        super().__init__(records)
        self.system_boot_result = Result('completed', '-1 ' + CURRENT + ' synthetic\n0 ' + BOOT + ' synthetic\n', 0)
        self.system_result = self.result
        self.system_requested, self.commands = [], []

    def run(self, command):
        self.commands.append(command)
        return self.system_boot_result if command == Command.JOURNAL_SYSTEM_BOOTS else self.boot_result

    def read_system_boot(self, boot_id):
        self.system_requested.append(boot_id)
        return self.system_result


class JournalScopeTests(unittest.TestCase):
    def test_default_scope_preserves_visible_selection_and_does_not_probe_system(self):
        runner = ScopedRunner([record()])
        data = diagnose(runner)
        self.assertEqual('visible', data['journal_scope']['requested'])
        self.assertEqual([Command.JOURNAL_BOOTS], runner.commands)
        self.assertEqual([BOOT], runner.requested)
        self.assertEqual([], runner.system_requested)
        self.assertEqual('unknown', data['journal_scope']['completeness'])

    def test_system_scope_resolves_index_against_same_scope_and_never_uses_visible_reader(self):
        runner = ScopedRunner([record()])
        data = diagnose(runner, 0, system_journal=True)
        self.assertEqual('system', data['journal_scope']['requested'])
        self.assertEqual(BOOT, data['selected_boot']['boot_id'])
        self.assertEqual([Command.JOURNAL_SYSTEM_BOOTS], runner.commands)
        self.assertEqual([BOOT], runner.system_requested)
        self.assertEqual([], runner.requested)
        self.assertEqual('available', data['state'])

    def test_failed_empty_or_invalid_system_listing_never_falls_back(self):
        for result in (Result('missing'), Result('timeout'), Result('output_limit'),
                       Result('completed', '', 1), Result('completed', '', 0), Result('completed', 'invalid', 0)):
            runner = ScopedRunner([record()])
            runner.system_boot_result = result
            data = diagnose(runner, 0, system_journal=True)
            self.assertEqual('unavailable', data['state'])
            self.assertIsNone(data['journal_collection'])
            self.assertEqual([], runner.system_requested)
            self.assertEqual([], runner.requested)
            self.assertEqual([Command.JOURNAL_SYSTEM_BOOTS], runner.commands)

    def test_system_collection_failure_and_parse_failure_have_safe_states_without_fallback(self):
        for result, parse in ((Result('timeout'), 'not_attempted'), (Result('completed', 'raw-private-stderr', 1), 'not_attempted'),
                              (Result('completed', 'malformed', 0), 'invalid'), (Result('completed', '', 0), 'empty')):
            runner = ScopedRunner([record()])
            runner.system_result = result
            data = diagnose(runner, 0, system_journal=True)
            self.assertEqual('unavailable', data['state'])
            self.assertEqual(parse, data['journal_collection']['parse_state'])
            self.assertEqual([], runner.requested)
            self.assertEqual('Unknown', data['root_cause'])
            self.assertNotIn('raw-private', json.dumps(data))

    def test_observed_system_evidence_is_counted_without_claiming_complete_access(self):
        values = [record(_TRANSPORT='kernel'), record(_PID='1', _COMM='systemd', _TRANSPORT='journal'),
                  record(_PID='42', _COMM='systemd', _TRANSPORT='journal'), record(message=[1, 2])]
        data = diagnose(ScopedRunner(values), 0, system_journal=True)
        scope = data['journal_scope']
        self.assertEqual(2, scope['kernel_records_examined'])
        self.assertEqual(1, scope['pid1_systemd_records_examined'])
        self.assertTrue(scope['system_evidence_observed'])
        self.assertEqual('unknown', scope['completeness'])
        self.assertEqual([], data['findings'])

    def test_user_only_tail_does_not_prove_missing_system_access(self):
        data = diagnose(ScopedRunner([record(_TRANSPORT='journal', _PID='42', _COMM='synthetic')]), 0, system_journal=True)
        self.assertFalse(data['journal_scope']['system_evidence_observed'])
        self.assertIn('does not establish absent system access', ' '.join(data['limitations']))
        self.assertEqual('unknown', data['journal_scope']['completeness'])

    def test_cli_supports_history_and_diagnose_but_rejects_other_commands(self):
        for command in ('history', 'diagnose'):
            for json_mode in (True, False):
                output = io.StringIO()
                main([command, '--system-journal'] + (['--boot', '0'] if command == 'diagnose' else []) + (['--json'] if json_mode else ['--details']),
                     runner=ScopedRunner([record()]), stdout=output)
                if json_mode:
                    self.assertEqual('system', json.loads(output.getvalue())['journal_scope']['requested'])
                    self.assertEqual('available', json.loads(output.getvalue())['state'])
                else:
                    self.assertIn('Journal scope: system;', output.getvalue())
        for command in ('status', 'check'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([command, '--system-journal'])

    def test_system_scope_validation_happens_before_any_command(self):
        for value in ('system', 1, None):
            with patch('faultlens.incidents.CommandRunner', side_effect=AssertionError('must not construct runner')):
                with self.assertRaises(ValueError):
                    history(system_journal=value)
        with patch('faultlens.commands._capture', side_effect=AssertionError('must not execute')):
            with self.assertRaises(ValueError):
                CommandRunner().read_system_boot('../private')

    def test_fixed_system_arguments_keep_boot_byte_and_record_limits(self):
        with patch('faultlens.commands.trusted_tool', return_value='/usr/bin/journalctl'), patch(
                'faultlens.commands._capture', return_value=Result('completed', '', 0)) as capture:
            runner = CommandRunner()
            runner.run(Command.JOURNAL_SYSTEM_BOOTS)
            listing_args = capture.call_args.args[0]
            runner.read_system_boot(BOOT)
            read_args = capture.call_args.args[0]
            runner.read_boot(BOOT)
            visible_args = capture.call_args.args[0]
        self.assertEqual(['/usr/bin/journalctl', '--system', '--list-boots', '--no-pager', '--quiet'], listing_args)
        self.assertIn('--system', read_args)
        self.assertNotIn('--system', visible_args)
        self.assertIn('--boot=' + BOOT, read_args)
        self.assertIn('--lines=501', read_args)
        self.assertIn('--output=json', read_args)
        self.assertFalse(any('sudo' in arg or '--file' in arg or '--directory' in arg for arg in read_args))

    def test_read_failure_is_visible_in_text_without_raw_output(self):
        runner = ScopedRunner()
        runner.system_result = Result('completed', 'synthetic-private-payload', 1)
        output = io.StringIO()
        main(['diagnose', '--boot', '0', '--system-journal', '--details'], runner=runner, stdout=output)
        self.assertIn('Journal collection:', output.getvalue())
        self.assertIn('not_attempted', output.getvalue())
        self.assertNotIn('synthetic-private-payload', output.getvalue())

    def test_pstore_still_runs_when_system_listing_fails(self):
        runner = ScopedRunner()
        runner.system_boot_result = Result('completed', '', 1)
        output = io.StringIO()
        main(['diagnose', '--system-journal', '--pstore', '--json'], runner=runner,
             pstore_collector=lambda: ([b'Kernel panic - not syncing: synthetic'], 0), stdout=output)
        data = json.loads(output.getvalue())
        self.assertEqual('unavailable', data['state'])
        self.assertEqual('available', data['pstore']['state'])
        self.assertEqual('unverified', data['pstore']['boot_identity'])
