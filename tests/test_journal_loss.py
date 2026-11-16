"""Synthetic journal-driver loss reports; no logging flood or host evidence."""
import io
import json
import unittest

from faultlens.cli import main
from faultlens.incidents import diagnose
from faultlens.journal import JOURNAL_DROPPED, JOURNAL_MISSED
from tests.test_incidents import JournalRunner, record
from tests.test_journal_range import RangeRunner


class JournalLossTests(unittest.TestCase):
    def test_structured_driver_reports_confirm_observations_only(self):
        for identity, rule in ((JOURNAL_DROPPED, 'journal.messages_suppressed'),
                               (JOURNAL_MISSED, 'journal.kernel_messages_missed')):
            data = diagnose(JournalRunner([record(_TRANSPORT='driver', MESSAGE_ID=identity)]))
            finding, = data['findings']
            self.assertEqual(rule, finding['rule_id'])
            self.assertEqual('Confirmed', finding['confidence'])
            self.assertEqual('Unknown', finding['cause_confidence'])
            self.assertEqual('Unknown', data['root_cause'])
            self.assertEqual('Unknown', data['shutdown_assessment'])
            self.assertEqual(rule, data['timeline'][0]['rule_id'])
            self.assertEqual({}, finding['reported_measurements'])

    def test_application_spoof_text_and_unknown_ids_do_not_match(self):
        for identity in (JOURNAL_DROPPED, JOURNAL_MISSED):
            for transport in ('journal', 'stdout', 'syslog', 'kernel', ''):
                data = diagnose(JournalRunner([record('Suppressed 42 messages from synthetic.service',
                    _TRANSPORT=transport, MESSAGE_ID=identity, _PID='1', _COMM='systemd')]))
                self.assertEqual([], data['findings'])
        for identity in ('', '0' * 32, JOURNAL_DROPPED.upper()):
            self.assertEqual([], diagnose(JournalRunner([record('Missed 42 kernel messages',
                _TRANSPORT='driver', MESSAGE_ID=identity)]))['findings'])

    def test_structured_id_survives_missing_binary_or_untrusted_message_content(self):
        for message in (None, [65, 66], 'x' * 8193, '\x1b]52;c;synthetic\x07\nprivate-unit.service'):
            data = diagnose(JournalRunner([record(message, _TRANSPORT='driver', MESSAGE_ID=JOURNAL_DROPPED)]))
            self.assertEqual(1, len(data['findings']))
            self.assertNotIn('private-unit', json.dumps(data))

    def test_readable_evidence_retains_source_while_json_requires_explicit_originals(self):
        for flags in ([], ['--json']):
            output = io.StringIO()
            main(['diagnose'] + flags, runner=JournalRunner([record(
                'Suppressed 987654 messages from private-unit.service', _TRANSPORT='driver',
                MESSAGE_ID=JOURNAL_DROPPED)]), stdout=output)
            if '--json' in flags:
                self.assertNotIn('private-unit',output.getvalue())
            else:
                self.assertIn('private-unit.service',output.getvalue())
            if '--json' in flags: self.assertNotIn('987654',output.getvalue())
            else: self.assertIn('Suppressed 987654',output.getvalue())
            self.assertIn('Journald reported suppressed messages', output.getvalue())

    def test_capped_repeated_reports_keep_unknown_coverage_and_causes(self):
        data = diagnose(JournalRunner([record(_TRANSPORT='driver', MESSAGE_ID=JOURNAL_MISSED,
            monotonic=index) for index in range(501)]))
        self.assertEqual(500, len(data['findings']))
        self.assertTrue(data['record_limit_reached'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertEqual('unknown', data['journal_window']['completeness'])

    def test_receipt_window_and_filtered_search_remain_separate(self):
        runner = RangeRunner([record(_TRANSPORT='driver', MESSAGE_ID=JOURNAL_DROPPED,
                                     realtime=1500)])
        data = diagnose(runner, since_us=1000, until_us=2000, search_events=True)
        self.assertEqual('journal.messages_suppressed', data['findings'][0]['rule_id'])
        self.assertTrue(all(not query['findings'] for query in data['event_search']['queries']))
        self.assertEqual(1500, data['reconstruction']['last_record']['realtime_us'])
