"""Invented Atop CPU accounting; no real load, contention or I/O injection."""
import io
import json
import unittest

from faultlens.atop import samples
from faultlens.cli import main
from faultlens.incidents import diagnose
from tests.test_atop import AtopRunner, sample

KEYS = ('cpu_execution_percent', 'cpu_idle_percent', 'cpu_iowait_percent', 'cpu_steal_percent')


def cpu_sample(ticks, *, reset=False):
    # Atop order: system, user, nice, idle, wait, IRQ, soft IRQ, steal, guest.
    return sample(reset=reset).replace('300 300 0 2400 0 0 0 0 1500', ' '.join(map(str, ticks)))


class AtopCpuTests(unittest.TestCase):
    def test_cpu_states_use_one_denominator_without_double_counting_guest(self):
        value, = samples(cpu_sample([10, 20, 5, 30, 15, 4, 6, 10, 20]))
        self.assertEqual([45, 30, 15, 10], [value[key] for key in KEYS])
        self.assertEqual(55, value['cpu_busy_percent'])
        self.assertEqual(100, sum(value[key] for key in KEYS))

    def test_pure_states_and_zero_ticks_keep_zero_distinct_from_unknown(self):
        for index, key in ((0, KEYS[0]), (3, KEYS[1]), (4, KEYS[2]), (7, KEYS[3])):
            ticks = [0] * 9
            ticks[index] = 100
            value, = samples(cpu_sample(ticks))
            self.assertEqual(100, value[key])
            self.assertTrue(all(value[other] == 0 for other in KEYS if other != key))
        for reset, ticks in ((False, [0] * 9), (True, [10] * 9)):
            value, = samples(cpu_sample(ticks, reset=reset))
            self.assertTrue(all(value[key] is None for key in KEYS + ('cpu_busy_percent',)))

    def test_large_counters_round_independently_without_clamping(self):
        value, = samples(cpu_sample([10**19, 0, 0, 10**19, 10**19, 0, 0, 0, 0]))
        self.assertEqual([33.33, 33.33, 33.33, 0], [value[key] for key in KEYS])
        self.assertAlmostEqual(99.99, sum(value[key] for key in KEYS))
        self.assertEqual(33.33, value['cpu_busy_percent'])

    def test_negative_wait_invalidates_samples_without_changing_journal_findings(self):
        text = cpu_sample([10, 20, 0, 30, -1, 0, 0, 0, 0])
        with self.assertRaises(ValueError):
            samples(text)
        data = diagnose(AtopRunner(text=text), atop_date='20260101')
        self.assertEqual('unavailable', data['atop']['state'])
        self.assertEqual('Confirmed', data['findings'][0]['confidence'])
        self.assertEqual('Unknown', data['root_cause'])

    def test_new_measurements_never_upgrade_temporal_pairing_or_create_findings(self):
        data = diagnose(AtopRunner(text=cpu_sample([0, 0, 0, 0, 50, 0, 0, 50, 0])), atop_date='20260101')
        self.assertEqual(50, data['atop']['samples'][0]['cpu_steal_percent'])
        self.assertEqual(1, len(data['findings']))
        self.assertEqual('Possible', data['atop']['correlations'][0]['confidence'])
        self.assertEqual('Unknown', data['root_cause'])
        self.assertEqual('Unknown', data['shutdown_assessment'])

    def test_cli_json_exposes_accounting_without_raw_host_or_messages(self):
        output = io.StringIO()
        main(['diagnose', '--atop-date', '20260101', '--json'], runner=AtopRunner(), stdout=output)
        value = json.loads(output.getvalue())['atop']['samples'][0]
        self.assertEqual([20, 80, 0, 0], [value[key] for key in KEYS])
        self.assertNotIn('synthetic.test', output.getvalue())
        self.assertIn('not proof of provider contention', output.getvalue())
