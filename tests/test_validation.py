"""Synthetic reference-tool comparisons; never inspect the CI host."""
import unittest
from unittest.mock import patch

from faultlens.collectors import percentage, status
from faultlens.commands import CATALOG, Command, Result
from faultlens.parsers import cpu
from faultlens.validation import compare, exit_code, filesystem_reference, memory_reference, validate
from tests.support import SyntheticRunner, SyntheticSources

MEMORY = ' total used free shared buff/cache available\nMem: 1024000 512000 100000 0 412000 512000\nSwap: 102400 25600 76800\n'
DISK = '1B-blocks Used Avail Use%\n4096000 2457600 1433600 64%\n'


class ValidationTests(unittest.TestCase):
    def test_reserved_blocks_keep_total_and_user_percent_distinct(self):
        data = {item.key: item for item in status(SyntheticSources(), SyntheticRunner(), sleep=lambda _: None)}
        self.assertEqual(60, data['filesystem.root.used'].value)
        self.assertEqual(63.16, data['filesystem.root.user_used'].value)
        self.assertEqual(64, filesystem_reference(DISK)['filesystem.root.user_used'])

    def test_thresholds_use_unrounded_measurements(self):
        self.assertEqual('normal', percentage('test', 89996, 100000, 'synthetic').state)
        self.assertEqual('warning', percentage('test', 94996, 100000, 'synthetic').state)
        self.assertEqual('critical', percentage('test', 95000, 100000, 'synthetic').state)

    def test_empty_cpu_input_is_explicitly_invalid(self):
        for text in ('', '\n'):
            with self.assertRaises(ValueError):
                cpu(text)

    def test_reference_parsers_reject_malformed_or_hostile_output(self):
        for parser, text in ((memory_reference, MEMORY.replace('512000', '-1')),
                             (memory_reference, 'Mem: access denied'),
                             (filesystem_reference, 'header\n1 2 3 999%'),
                             (filesystem_reference, 'header\n1 0 1 NaN%')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parser(text)

    def test_validation_matches_synthetic_oracle_without_values(self):
        runner = SyntheticRunner()
        runner.results.update({Command.REFERENCE_MEMORY: Result('completed', MEMORY, 0),
                               Command.REFERENCE_FILESYSTEM: Result('completed', DISK, 0)})
        with patch('faultlens.validation.time.clock_gettime', return_value=1000.5):
            result = validate(sources=SyntheticSources(), runner=runner, kernel='6.1.0-synthetic')
        self.assertEqual(0, exit_code(result))
        for item in result['comparisons']:
            self.assertEqual({'key', 'state'}, set(item))
            self.assertEqual('pass', item['state'])

    def test_missing_tool_is_incomplete_not_a_pass(self):
        runner = SyntheticRunner()
        runner.results.update({Command.REFERENCE_MEMORY: Result('missing'),
                               Command.REFERENCE_FILESYSTEM: Result('timeout')})
        with patch('faultlens.validation.time.clock_gettime', return_value=1000.5):
            result = validate(sources=SyntheticSources(), runner=runner, kernel='6.1.0-synthetic')
        self.assertEqual(2, exit_code(result))

    def test_real_difference_is_a_mismatch_not_silently_skipped(self):
        observations = status(SyntheticSources(), SyntheticRunner(), sleep=lambda _: None)
        result = compare(observations, {'memory.total': 2048000})
        self.assertEqual('mismatch', next(item['state'] for item in result if item['key'] == 'memory.total'))
        self.assertEqual(1, exit_code({'comparisons': result}))

    def test_boot_listing_explicitly_disables_legend(self):
        self.assertIn('--no-legend', CATALOG[Command.JOURNAL_BOOTS][1])
