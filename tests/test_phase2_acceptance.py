"""Integrated phase 2 walkthrough using invented sources and no native processes."""
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from tests.support import SyntheticEventRunner, SyntheticOverviewRunner, SyntheticSources, SyntheticExtendedRunner


class Phase2AcceptanceTests(unittest.TestCase):
    def test_read_only_investigation_flow_uses_synthetic_sources_only(self):
        sources = SyntheticSources()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch(
                'subprocess.Popen', side_effect=AssertionError('native processes forbidden')):
            for arguments, runner in (
                    (['check', '--history'], SyntheticEventRunner()),
                    (['history', '--system-journal'], SyntheticEventRunner()),
                    (['incidents', '--boot-count', '7'], SyntheticOverviewRunner()),
                    (['diagnose', '--boot-id', 'a' * 32, '--system-journal', '--search-events',
                      '--since-us', '1767225600000000', '--until-us', '1767225600000500',
                      '--atop-date', '20260101', '--atop-extended', '--pstore', '--pstore-archive'], SyntheticExtendedRunner())):
                output = io.StringIO()
                self.assertEqual(0, main(arguments + ['--json'], runner=runner, sources=sources,
                    pstore_collector=sources.pstore_snapshot, pstore_archive_collector=sources.pstore_snapshot,
                    stdout=output))
                data = json.loads(output.getvalue())
                self.assertEqual(arguments[0], data['command'])
                if arguments[0] == 'diagnose':
                    self.assertEqual('available', data['state'])
                    self.assertEqual('available', data['event_search']['state'])
                    self.assertEqual('available', data['atop']['state'])
                    self.assertEqual('available', data['atop']['samples'][0]['extended']['state'])
                    self.assertEqual('available', data['pstore']['state'])
                    self.assertEqual('available', data['pstore_archive']['state'])
                    self.assertEqual(500, data['records_examined'])
                    self.assertTrue(data['record_limit_reached'])
                    self.assertEqual('Unknown', data['root_cause'])
                    self.assertEqual('Unknown', data['shutdown_assessment'])
                    self.assertEqual('unverified', data['pstore']['boot_identity'])
                    self.assertEqual('unverified', data['pstore_archive']['boot_identity'])
                    self.assertTrue(all(value['confidence'] == 'Possible' for value in data['atop']['correlations']))
                self.assertNotIn('synthetic.test', output.getvalue())
                self.assertNotIn('synthetic kernel context', output.getvalue())

    def test_optional_source_failures_preserve_journal_findings(self):
        from faultlens.commands import Result
        runner = SyntheticEventRunner()
        runner.read_atop = lambda *args: Result('unavailable')
        output = io.StringIO()
        def inaccessible():
            raise PermissionError('private source details')
        self.assertEqual(0, main(['diagnose', '--boot', '-1', '--atop-date', '20260101',
                                '--pstore', '--pstore-archive', '--json'], runner=runner,
                                pstore_collector=inaccessible, pstore_archive_collector=inaccessible,
                                stdout=output))
        data = json.loads(output.getvalue())
        self.assertEqual('available', data['state'])
        self.assertEqual(500, len(data['findings']))
        for key in ('atop', 'pstore', 'pstore_archive'):
            self.assertEqual('unavailable', data[key]['state'])
        self.assertNotIn('private source details', output.getvalue())
