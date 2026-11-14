"""Invented detector messages only; no live lockups, fault injection or host logs."""
import io
import json
import unittest

from faultlens.cli import main
from faultlens.incidents import diagnose
from tests.test_atop import AtopRunner, sample, EPOCH
from tests.test_incidents import JournalRunner, record

SOFT = 'watchdog: BUG: soft lockup - CPU#2 stuck for 26s! [synthetic-task:42]'
HARD = 'watchdog: Watchdog detected hard LOCKUP on cpu 3'
HUNG = 'INFO: task synthetic-task:42 blocked for more than 120 seconds.'


class StallRuleTests(unittest.TestCase):
    def test_supported_reports_have_checked_measurements_and_unknown_causes(self):
        for message, rule, measurements in (
                (SOFT, 'kernel.soft_lockup', {'reported_cpu_index': 2, 'reported_stuck_seconds': 26}),
                (HARD, 'kernel.hard_lockup', {'reported_cpu_index': 3}),
                (HARD.replace('watchdog:', 'NMI watchdog:'), 'kernel.hard_lockup', {'reported_cpu_index': 3}),
                (HUNG, 'kernel.hung_task', {'reported_blocked_more_than_seconds': 120})):
            for suffix in ('', '\n'):
                with self.subTest(rule=rule, suffix=suffix):
                    data = diagnose(JournalRunner([record(message + suffix)]))
                    finding, = data['findings']
                    self.assertEqual(rule, finding['rule_id'])
                    self.assertEqual(measurements, finding['reported_measurements'])
                    self.assertEqual('Confirmed', finding['confidence'])
                    self.assertEqual('Unknown', finding['cause_confidence'])
                    self.assertEqual('Unknown', data['root_cause'])
                    self.assertEqual('Unknown', data['shutdown_assessment'])
                    self.assertEqual(rule, data['timeline'][0]['rule_id'])
                    self.assertTrue(finding['recommendations'])
                    self.assertNotIn('synthetic-task', json.dumps(data))

    def test_application_mentions_partial_and_embedded_messages_do_not_match(self):
        for message in (SOFT, HARD, HUNG):
            self.assertEqual([], diagnose(JournalRunner([record(message, _TRANSPORT='stdout')]))['findings'])
            for text in ('Example: ' + message, message + ' extra', 'documentation\n' + message,
                         message + '\nspoofed event', message[:-1], message.replace('watchdog:', 'application:')):
                if text == message:
                    continue
                self.assertEqual([], diagnose(JournalRunner([record(text)]))['findings'], text)
        for text in ('soft lockup', 'Hard LOCKUP', 'INFO: task blocked', 'NMI watchdog: enabled'):
            self.assertEqual([], diagnose(JournalRunner([record(text)]))['findings'])

    def test_oversized_negative_fractional_zero_and_out_of_range_fields_are_rejected(self):
        invalid = [SOFT.replace('26s', value + 's') for value in ('0', '-1', '1.5', '4294967296', '9' * 50)]
        invalid += [HARD.replace('cpu 3', 'cpu ' + value) for value in ('-1', '2147483648', '9' * 50, 'NaN')]
        invalid += [HUNG.replace('120 seconds', value + ' seconds') for value in ('0', '-1', '9223372036854775808', '1.5')]
        invalid += [SOFT.replace(':42]', ':2147483648]'), HUNG.replace(':42 ', ':2147483648 ')]
        for text in invalid:
            self.assertEqual([], diagnose(JournalRunner([record(text)]))['findings'], text)

    def test_task_name_controls_and_multiline_injection_fail_closed(self):
        for message in (SOFT, HUNG):
            for name in ('synthetic\x1b]52;c;hidden\x07', 'synthetic\nspoof', 'synthetic\x00payload', 'x' * 65):
                text = message.replace('synthetic-task', name)
                self.assertEqual([], diagnose(JournalRunner([record(text)]))['findings'])
        data = diagnose(JournalRunner([record(SOFT.replace('synthetic-task', 'synthetic:task'))]))
        self.assertEqual(1, len(data['findings']))

    def test_cli_redacts_task_names_and_raw_messages_in_text_and_json(self):
        for json_mode in (True, False):
            output = io.StringIO()
            main(['diagnose'] + (['--json'] if json_mode else []),
                 runner=JournalRunner([record(SOFT)]), stdout=output)
            text = output.getvalue()
            self.assertNotIn('synthetic-task', text)
            self.assertNotIn('stuck for 26s!', text)
            self.assertIn('reported_stuck_seconds', text)
            if not json_mode:
                self.assertIn('Confirmed report; cause Unknown', text)

    def test_monotonic_order_and_repeated_reports_are_retained_without_outage_inference(self):
        data = diagnose(JournalRunner([record(HARD, monotonic=300, realtime=10),
                                      record(HUNG, monotonic=100, realtime=30),
                                      record(HARD, monotonic=200, realtime=20)]))
        self.assertEqual(['kernel.hung_task', 'kernel.hard_lockup', 'kernel.hard_lockup'],
                         [value['rule_id'] for value in data['timeline']])
        self.assertEqual('Unknown', data['shutdown_assessment'])
        self.assertEqual('Unknown', data['root_cause'])

    def test_record_cap_and_repeated_reports_never_become_outage_counts(self):
        data = diagnose(JournalRunner([record(SOFT, monotonic=index) for index in range(501)]))
        self.assertEqual(500, len(data['findings']))
        self.assertTrue(data['record_limit_reached'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertTrue(all(item['reported_measurements']['reported_stuck_seconds'] == 26 for item in data['findings']))

    def test_atop_pairing_remains_possible_for_new_events(self):
        runner = AtopRunner(records=[record(SOFT, realtime=(EPOCH + 15) * 1000000, monotonic=15000000)], text=sample())
        data = diagnose(runner, atop_date='20260101')
        self.assertEqual('kernel.soft_lockup', data['findings'][0]['rule_id'])
        self.assertEqual('Possible', data['atop']['correlations'][0]['confidence'])
        self.assertEqual('Unknown', data['root_cause'])
