"""Invented journal records only; never collect journal data from the CI host."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import Command, CommandRunner, Result
from faultlens.incidents import SHUTDOWN_REQUEST, UNIT_START_FAILED, analyze, diagnose, history
from faultlens.journal import MAX_RECORDS, boots, entries

BOOT = 'a' * 32
CURRENT = 'b' * 32


def record(message='Synthetic event', *, monotonic=100, realtime=1767225600000000, **fields):
    value = {'_BOOT_ID': BOOT, '__REALTIME_TIMESTAMP': str(realtime),
             '__MONOTONIC_TIMESTAMP': str(monotonic), '_TRANSPORT': 'kernel', 'MESSAGE': message}
    value.update(fields)
    return value


def listing(records):
    return '\n'.join(json.dumps(item) for item in records)


class JournalRunner:
    def __init__(self, records=()):
        self.boot_result = Result('completed', '-1 ' + BOOT + ' synthetic\n0 ' + CURRENT + ' synthetic\n', 0)
        self.result = Result('completed', listing(records), 0)
        self.requested = []

    def run(self, command):
        assert command == Command.JOURNAL_BOOTS
        return self.boot_result

    def read_boot(self, identity):
        self.requested.append(identity)
        return self.result


class JournalParserTests(unittest.TestCase):
    def test_listing_is_normalized_without_untrusted_date_text(self):
        value = boots('-1 ' + BOOT + ' secret-host-text\n0 ' + CURRENT + ' synthetic')
        self.assertEqual([0, -1], [boot.index for boot in value])
        self.assertNotIn('secret-host-text', str(value))

    def test_duplicate_id_or_index_and_positive_boot_are_rejected(self):
        for text in ('-1 ' + BOOT + ' x\n-1 ' + CURRENT + ' x',
                     '-1 ' + BOOT + ' x\n0 ' + BOOT + ' x',
                     '1 ' + BOOT + ' x', '-1 not-an-id x', 'IDX BOOT ID FIRST LAST'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                boots(text)

    def test_boot_listing_and_record_byte_limits_fail_closed(self):
        with self.assertRaises(ValueError):
            boots('x' * 262145)
        with self.assertRaises(ValueError):
            entries('x' * 262145, BOOT)
        with self.assertRaises(ValueError):
            boots('\n'.join(f'{-i} {i:032x} synthetic' for i in range(129)))

    def test_monotonic_order_survives_wall_clock_reversal(self):
        result, limited, unsupported = entries(listing([
            record(monotonic=200, realtime=10), record(monotonic=100, realtime=20)]), BOOT)
        self.assertEqual([100, 200], [entry.monotonic_us for entry in result])
        self.assertFalse(limited)
        self.assertEqual(0, unsupported)

    def test_cap_is_reported_and_oldest_record_is_omitted(self):
        parsed, limited, _ = entries(listing(record(monotonic=i) for i in range(MAX_RECORDS + 1)), BOOT)
        self.assertTrue(limited)
        self.assertEqual(MAX_RECORDS, len(parsed))
        self.assertEqual(1, parsed[0].monotonic_us)
        with self.assertRaises(ValueError):
            entries(listing(record(monotonic=i) for i in range(MAX_RECORDS + 2)), BOOT)

    def test_mixed_boots_invalid_timestamps_and_metadata_are_rejected(self):
        for fields in ({'_BOOT_ID': CURRENT}, {'__REALTIME_TIMESTAMP': 'NaN'},
                       {'__REALTIME_TIMESTAMP': str(10**20)}, {'__MONOTONIC_TIMESTAMP': '-1'},
                       {'_PID': ['1']}, {'__CURSOR': '\x1b]52;c;synthetic'}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                entries(listing([record(**fields)]), BOOT)

    def test_duplicate_json_keys_and_cursors_are_rejected(self):
        with self.assertRaises(ValueError):
            entries('{"MESSAGE":"a","MESSAGE":"b"}', BOOT)
        with self.assertRaises(ValueError):
            entries(listing([record(__CURSOR='s=synthetic'), record(__CURSOR='s=synthetic')]), BOOT)

    def test_binary_and_oversized_messages_leave_explicit_gaps(self):
        parsed, _, unsupported = entries(listing([record(message=[1, 2]), record(message='x' * 8193)]), BOOT)
        self.assertEqual(2, unsupported)
        self.assertTrue(all(entry.message is None for entry in parsed))
        self.assertEqual([], analyze(parsed))


class RuleTests(unittest.TestCase):
    def findings(self, *values):
        return analyze(entries(listing(values), BOOT)[0])

    def test_kernel_events_are_confirmed_but_causes_are_unknown(self):
        patterns = [('Out of memory: Killed process 42 (synthetic)', 'kernel.oom'),
                    ('Memory cgroup out of memory: Killed process 42', 'kernel.oom'),
                    ('Kernel panic - not syncing: synthetic', 'kernel.panic'),
                    ('Buffer I/O error on dev synthetic', 'kernel.io_error'),
                    ('EXT4-fs error (device synthetic): example', 'kernel.filesystem_error')]
        for message, expected in patterns:
            with self.subTest(expected=expected):
                finding, = self.findings(record(message))
                self.assertEqual(expected, finding.rule_id)
                self.assertEqual('Confirmed', finding.confidence)
                self.assertEqual('Unknown', finding.cause_confidence)
                self.assertTrue(finding.evidence)
                self.assertTrue(finding.reasoning)
                self.assertTrue(finding.recommendations)

    def test_application_mentions_and_loose_keywords_do_not_confirm_events(self):
        for value in (record('Kernel panic - not syncing: synthetic', _TRANSPORT='stdout'),
                      record('Example documentation mentioning Out of memory: Killed process 1'),
                      record('panic is possible'), record('Out of memory: Killed process unknown')):
            self.assertEqual([], self.findings(value))

    def test_structured_systemd_ids_require_trusted_pid_one_metadata(self):
        value = record(_TRANSPORT='journal', _PID='1', _COMM='systemd', MESSAGE_ID=UNIT_START_FAILED)
        self.assertEqual('systemd.start_job_failed', self.findings(value)[0].rule_id)
        for changed in ({'_PID': '42'}, {'_COMM': 'application'}):
            forged = dict(value, **changed)
            self.assertEqual([], self.findings(forged))

    def test_shutdown_marker_is_not_proof_of_successful_shutdown(self):
        runner = JournalRunner([record(_PID='1', _COMM='systemd', MESSAGE_ID=SHUTDOWN_REQUEST)])
        data = diagnose(runner)
        self.assertEqual('Marker observed; completion unknown', data['shutdown_assessment'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertIn('Initiation does not prove', data['findings'][0]['limitations'][0])

    def test_absent_marker_is_unknown_not_an_unexpected_reboot(self):
        data = diagnose(JournalRunner([record()]))
        self.assertEqual('Unknown', data['shutdown_assessment'])
        self.assertEqual([], data['findings'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertIsNotNone(data['last_record'])


class HistoricalCollectionTests(unittest.TestCase):
    def test_resolves_relative_selection_to_id_and_redacts_raw_fields(self):
        marker = 'synthetic-private-payload'
        runner = JournalRunner([record('Kernel panic - not syncing: ' + marker, __CURSOR='s=' + marker)])
        data = diagnose(runner)
        self.assertEqual([BOOT], runner.requested)
        serialized = json.dumps(data)
        self.assertNotIn(marker, serialized)
        self.assertIn('cursor_sha256', serialized)
        self.assertEqual('bounded_tail', data['coverage'])

    def test_empty_denied_and_malformed_records_never_produce_healthy_history(self):
        for result in (Result('missing'), Result('timeout'), Result('output_limit'),
                       Result('completed', '', 0), Result('completed', 'permission denied', 1),
                       Result('completed', 'not JSON', 0)):
            runner = JournalRunner()
            runner.result = result
            data = diagnose(runner)
            self.assertEqual('unavailable', data['state'])
            self.assertEqual('Unknown', data['root_cause'])
            self.assertEqual([], data['findings'])

    def test_missing_boot_does_not_query_current_boot_as_a_fallback(self):
        runner = JournalRunner()
        data = diagnose(runner, -2)
        self.assertEqual([], runner.requested)
        self.assertEqual('unavailable', data['state'])

    def test_invalid_boot_listing_is_not_used_for_commands(self):
        runner = JournalRunner()
        runner.boot_result = Result('completed', '-1 ;unsafe fake', 0)
        self.assertEqual('unavailable', history(runner)['state'])
        self.assertEqual([], runner.requested)

    def test_cli_history_and_diagnose_render_safe_metadata_only(self):
        runner = JournalRunner([record('Kernel panic - not syncing: \x1b]52;c;private\x07')])
        for args in (['history'], ['diagnose', '--previous-boot'], ['diagnose', '--json']):
            output = io.StringIO()
            self.assertEqual(0, main(args, runner=runner, stdout=output))
            self.assertNotIn('\x1b', output.getvalue())
            self.assertNotIn('52;c', output.getvalue())
            self.assertNotIn('private', output.getvalue())

    def test_cli_rejects_unsafe_or_misplaced_boot_selection(self):
        for args in (['diagnose', '--boot', '1'], ['diagnose', '--boot', '-129'],
                     ['history', '--boot', '-1'], ['status', '--previous-boot'],
                     ['diagnose', '--boot', ';unsafe']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                main(args)
            self.assertEqual(2, result.exception.code)

    def test_runner_validates_scope_before_invoking_any_tool(self):
        for identity in ('-1', BOOT + ';unsafe', '../synthetic', '', 1):
            with patch('faultlens.commands._capture', side_effect=AssertionError('must not execute')):
                with self.assertRaises(ValueError):
                    CommandRunner().read_boot(identity)
        with patch('faultlens.commands.trusted_tool', return_value='/usr/bin/journalctl'), patch(
                'faultlens.commands._capture', return_value=Result('completed', '', 0)) as capture:
            CommandRunner().read_boot(BOOT)
        argv = capture.call_args.args[0]
        self.assertIn('--boot=' + BOOT, argv)
        self.assertIn('--lines=501', argv)
        self.assertIn('--output=json', argv)
