"""Invented SSH reports and administrator evidence views; no real authentication logs."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import CommandRunner, Result
from faultlens.incidents import diagnose
from faultlens.journal import entries
from faultlens.ssh import classify
from tests.test_incidents import BOOT, JournalRunner, record
from tests.test_event_search import SearchRunner
from tests.test_journal_range import RangeRunner

FAILED = 'Failed password for invalid user synthetic-admin from 192.0.2.7 port 2222 ssh2'
ACCEPTED = 'Accepted password for synthetic-admin from 2001:db8::7 port 2222 ssh2'
INVALID = 'Invalid user synthetic-admin from 192.0.2.7 port 2222'


def ssh_record(message=FAILED, **kwargs):
    fields = dict(_UID='0', _COMM='sshd', _PID='42', _TRANSPORT='syslog', PRIORITY='6')
    fields.update(kwargs)
    return record(message, **fields)


class SshRunner(RangeRunner):
    def __init__(self, records=(), ssh=()):
        super().__init__(records)
        self.ssh_result = Result('completed', '\n'.join(json.dumps(row) for row in ssh), 0)
        self.ssh_calls = []

    def read_ssh_candidates(self, boot_id, **options):
        self.ssh_calls.append((boot_id, options))
        return self.ssh_result


class SshAnalysisTests(unittest.TestCase):
    def test_supported_reports_keep_admin_identities_and_original_evidence(self):
        runner = SshRunner(ssh=[ssh_record(FAILED), ssh_record(ACCEPTED, monotonic=200), ssh_record(INVALID, monotonic=300)])
        data = diagnose(runner, search_ssh=True)['ssh_analysis']
        self.assertEqual('available', data['state'])
        self.assertEqual({'ssh.password_failed': 1, 'ssh.password_accepted': 1, 'ssh.invalid_user_report': 1}, data['finding_counts_by_rule'])
        for value in data['findings']:
            self.assertEqual('Confirmed', value['confidence'])
            self.assertEqual('Unknown', value['cause_confidence'])
            self.assertEqual('synthetic-admin', value['evidence'][0]['username'])
            self.assertEqual(2222, value['evidence'][0]['peer_port'])
        self.assertEqual('2001:db8::7', data['findings'][1]['evidence'][0]['peer_address'])
        self.assertEqual(FAILED, data['records'][0]['message'])
        self.assertEqual('Unknown', data['attack_assessment'])

    def test_default_diagnosis_does_not_collect_ssh(self):
        runner = SshRunner()
        self.assertNotIn('ssh_analysis', diagnose(runner))
        self.assertEqual([], runner.ssh_calls)

    def test_all_supported_process_names_and_exact_source_constraints(self):
        for comm in ('sshd', 'sshd-session', 'sshd-auth'):
            data = diagnose(SshRunner(ssh=[ssh_record(_COMM=comm)]), search_ssh=True)
            self.assertEqual(1, len(data['ssh_analysis']['findings']))
        for overrides in ({'_UID': '1000'}, {'_UID': ''}, {'_TRANSPORT': 'stdout'}, {'_COMM': 'application'}):
            row = ssh_record(**overrides)
            entry, = entries(json.dumps(row), BOOT)[0]
            self.assertIsNone(classify(entry))
            data = diagnose(SshRunner(ssh=[row]), search_ssh=True)['ssh_analysis']
            self.assertEqual('invalid', data['parse_state'])
            self.assertEqual([], data['records'])

    def test_formats_do_not_accept_embedded_or_ambiguous_reports(self):
        for message in ('Example: '+FAILED, FAILED+' extra', FAILED+'\n'+ACCEPTED,
                        FAILED.replace('192.0.2.7', '999.1.1.1'), FAILED.replace('2222', '65536'),
                        FAILED.replace('2222', '0'), FAILED.replace('password', 'publickey'),
                        FAILED.replace('Failed', 'Partial'), ACCEPTED.replace('password', 'password/pam')):
            data = diagnose(SshRunner(ssh=[ssh_record(message)]), search_ssh=True)['ssh_analysis']
            self.assertEqual([], data['findings'])
            self.assertEqual(message, data['records'][0]['message'])
            self.assertEqual(1, data['unclassified_candidates'])
        for suffix in ('', '\n', ' [preauth]'):
            self.assertEqual(1, len(diagnose(SshRunner(ssh=[ssh_record(FAILED+suffix)]), search_ssh=True)['ssh_analysis']['findings']))

    def test_window_identity_and_scope_are_consistent_without_latest_fallback(self):
        runner = SshRunner(ssh=[ssh_record(realtime=1500)])
        data = diagnose(runner, boot_id=BOOT, system_journal=True, since_us=1000, until_us=2000, search_ssh=True)
        self.assertEqual([(BOOT, {'system':True, 'since_us':1000, 'until_us':2000})], runner.ssh_calls)
        self.assertEqual(1, len(data['ssh_analysis']['findings']))

    def test_invalid_sentinel_or_out_of_window_records_reject_whole_query(self):
        for rows in ([ssh_record(_BOOT_ID='c'*32)], [ssh_record(realtime=999)],
                     [ssh_record(_UID='1000', monotonic=0, realtime=1500)] + [ssh_record(monotonic=i+1, realtime=1500) for i in range(500)]):
            data = diagnose(SshRunner(ssh=rows), since_us=1000, until_us=2000, search_ssh=True)['ssh_analysis']
            self.assertEqual('invalid', data['parse_state'])
            self.assertEqual([], data['findings'])

    def test_cap_counts_reports_not_unique_attempts_and_keeps_filter_separate(self):
        data = diagnose(SshRunner(ssh=[ssh_record(monotonic=i) for i in range(501)]), search_ssh=True)
        ssh = data['ssh_analysis']
        self.assertTrue(ssh['record_limit_reached'])
        self.assertEqual(500, ssh['candidates_examined'])
        self.assertEqual(500, ssh['finding_counts_by_rule']['ssh.password_failed'])
        self.assertEqual([], data['findings'])
        self.assertEqual('Unknown', data['shutdown_assessment'])

    def test_collection_failure_and_empty_results_do_not_assert_security(self):
        for result in (Result('timeout'), Result('output_limit'), Result('completed', 'private source error', 1), Result('completed', '', 0)):
            runner = SshRunner()
            runner.ssh_result = result
            data = diagnose(runner, search_ssh=True)['ssh_analysis']
            self.assertEqual('Unknown', data['attack_assessment'])
            self.assertEqual([], data['findings'])
            self.assertNotIn('private source error', json.dumps(data))
            self.assertEqual(1, len(runner.ssh_calls))

    def test_unresolved_boot_never_runs_query_and_invalid_api_flags_fail(self):
        runner = SshRunner()
        runner.boot_result = Result('missing')
        self.assertEqual('boot_scope_unresolved', diagnose(runner, search_ssh=True)['ssh_analysis']['reason'])
        self.assertEqual([], runner.ssh_calls)
        with self.assertRaises(ValueError):
            diagnose(SshRunner(), search_ssh=1)

    def test_fixed_native_query_has_no_user_patterns_and_includes_root_metadata(self):
        with patch('faultlens.commands.trusted_tool', return_value='/usr/bin/journalctl'), patch(
                'faultlens.commands._capture', return_value=Result('completed', '', 0)) as capture:
            CommandRunner().read_ssh_candidates(BOOT, system=True, since_us=1000, until_us=2000)
        args = capture.call_args.args[0]
        for value in ('--system', '_UID=0', '_TRANSPORT=syslog', '_COMM=sshd', '_COMM=sshd-session',
                      '_COMM=sshd-auth', '--since=@0.001000', '--until=@0.002000', '--lines=501'):
            self.assertIn(value, args)
        self.assertTrue(any(value.startswith('--output-fields=') and '_UID' in value for value in args))
        self.assertFalse(any('grep' in value for value in args))

    def test_cli_scope_and_terminal_escaping_do_not_hide_original_content(self):
        for command in ('network', 'security', 'incidents', 'history'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([command, '--search-ssh'])
        message = 'synthetic-user\x1b]52;c;payload\x07\nunsupported ssh text'
        output = io.StringIO()
        main(['diagnose', '--search-ssh', '--details'], runner=SshRunner(ssh=[ssh_record(message)]), stdout=output)
        self.assertNotIn('\x1b', output.getvalue())
        self.assertIn('payload', output.getvalue())
        self.assertIn('\\u001b', output.getvalue())


class AdministratorEvidenceTests(unittest.TestCase):
    def test_original_message_and_cursor_are_locally_available_without_anonymization(self):
        original = 'Synthetic operator message for user=synthetic-admin peer=192.0.2.7'
        row = record(original, __CURSOR='s=synthetic;i=1')
        data = diagnose(JournalRunner([row]), show_evidence=True)
        value, = data['journal_records']
        self.assertEqual(original, value['message'])
        self.assertEqual('s=synthetic;i=1', value['reference']['cursor'])
        self.assertNotIn('journal_records', diagnose(JournalRunner([row])))

    def test_binary_and_oversized_analysis_text_remain_inspectable(self):
        for content in ([65, 0, 66], 'synthetic-content '*600):
            data = diagnose(JournalRunner([record(content)]), show_evidence=True)
            self.assertEqual(content, data['journal_records'][0]['message'])
            self.assertFalse(data['journal_records'][0]['analysis_text_available'])

    def test_filtered_evidence_is_available_and_controls_are_escaped_on_terminal(self):
        runner = SearchRunner(kernel=[record('synthetic\x1b[31m', PRIORITY='3')])
        data = diagnose(runner, search_events=True, show_evidence=True)
        self.assertEqual('synthetic\x1b[31m', data['event_search']['queries'][0]['records'][0]['message'])
        output = io.StringIO()
        main(['diagnose', '--show-evidence'], runner=JournalRunner([record('synthetic\x1b[31m')]), stdout=output)
        self.assertIn('\\u001b', output.getvalue())
        self.assertNotIn('\x1b', output.getvalue())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['network', '--show-evidence'])


class OriginalEvidenceValidationTests(unittest.TestCase):
    def test_nonfinite_or_excessively_nested_original_values_fail_closed(self):
        for value in (float('nan'), float('inf')):
            data = diagnose(JournalRunner([record(value)]), show_evidence=True)
            self.assertEqual('invalid', data['journal_collection']['parse_state'])
            self.assertEqual([], data['journal_records'])
        runner = JournalRunner()
        runner.result = Result('completed', json.dumps(record(1)).replace('\"MESSAGE\": 1', '\"MESSAGE\": 1e999'), 0)
        self.assertEqual('invalid', diagnose(runner, show_evidence=True)['journal_collection']['parse_state'])
        value = 'synthetic'
        for _ in range(40):
            value = [value]
        data = diagnose(JournalRunner([record(value)]), show_evidence=True)
        self.assertEqual('invalid', data['journal_collection']['parse_state'])
        self.assertEqual([], data['journal_records'])
