"""Exercise the real CLI in fresh processes against synthetic input only."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class ResourceBudgetTests(unittest.TestCase):
    def test_synthetic_cli_stays_within_foundation_budget(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/benchmark.py'
        result = subprocess.run([sys.executable, '-I', str(script), '--iterations', '2'],
                                capture_output=True, text=True, check=True, timeout=15)
        report = json.loads(result.stdout)
        self.assertTrue(report['synthetic'])
        self.assertEqual({'status', 'check', 'history', 'diagnose'}, set(report['commands']))
        for command, measurements in report['commands'].items():
            with self.subTest(command=command):
                self.assertTrue(measurements['within_regression_budget'])
                self.assertLess(measurements['peak_rss_max_mib'], 50)
