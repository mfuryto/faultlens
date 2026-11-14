"""Synthetic preservation settings and metadata; no real host configuration in CI."""
import contextlib
import io
import json
from types import SimpleNamespace
import stat
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import Command, Result
from faultlens.linux import LinuxSources
from faultlens.preservation import assess, atop_defaults, capacity, journal_config, seconds
from tests.support import SyntheticRunner, SyntheticSources


class ConfigurationTests(unittest.TestCase):
    def test_merged_directive_order_sections_and_unset_defaults(self):
        text = '''# /usr/lib/systemd/journald.conf
[Journal]
Storage=volatile
SystemMaxUse=64M
# /etc/systemd/journald.conf.d/20-synthetic.conf
[Journal]
Storage=persistent
MaxRetentionSec=1week 2day
[Other]
Storage=none
'''
        values, states = journal_config(text)
        self.assertEqual('persistent', values['Storage'])
        self.assertEqual(64 * 1024**2, values['SystemMaxUse'])
        self.assertEqual(9 * 86400, values['MaxRetentionSec'])
        self.assertEqual('explicit', states['Storage'])
        self.assertIsNone(values['RuntimeMaxUse'])
        self.assertEqual('unspecified', states['RuntimeMaxUse'])

    def test_unsupported_final_values_are_unknown_not_previous_values(self):
        values, states = journal_config('[Journal]\nStorage=persistent\nStorage=unsupported\nSystemMaxUse=\n')
        self.assertIsNone(values['Storage'])
        self.assertEqual('unsupported', states['Storage'])
        self.assertEqual('unsupported', states['SystemMaxUse'])

    def test_boundaries_and_unfinished_continuations_fail_closed(self):
        for text in ('[Journal]\nStorage=persistent\n# /etc/systemd/journald.conf.d/30-synthetic.conf\nStorage=volatile',
                     '[Journal]\nSystemMaxUse=1\\', '[Journal\nStorage=persistent',
                     '[Journal]\n# /unexpected/private-file\nStorage=persistent', 'x' * 262145):
            with self.subTest(text=text[:35]), self.assertRaises(ValueError):
                journal_config(text)

    def test_continuations_comments_and_explicit_zero_are_supported(self):
        values, states = journal_config('[Journal]\nMaxRetentionSec=1h \\\n# comment\n30min\nSystemMaxUse=0\n')
        self.assertEqual(5400, values['MaxRetentionSec'])
        self.assertEqual(0, values['SystemMaxUse'])
        self.assertEqual('explicit', states['SystemMaxUse'])
        self.assertEqual(0, seconds('0'))
        self.assertEqual(5 * 1024**3, capacity('5G'))
        for value in ('1month', 'infinity', '1 2', '-1s', 'private-text'):
            with self.assertRaises(ValueError):
                seconds(value)
        for value in ('1.5G', '1GB', '-1', '999999999999999999E'):
            with self.assertRaises(ValueError):
                capacity(value)

    def test_literal_defaults_are_hints_without_source_evaluation(self):
        values = atop_defaults('LOGINTERVAL="600" # $COMMENT ignored\nLOGGENERATIONS=28\nLOGPATH=/var/log/atop\nLOGOPTS="-R"\n')
        self.assertEqual(600, values['LOGINTERVAL'])
        self.assertEqual(28, values['LOGGENERATIONS'])
        self.assertTrue(values['standard_path'])
        self.assertFalse(atop_defaults('LOGPATH=/custom/synthetic-location')['standard_path'])
        self.assertEqual({}, atop_defaults('# only a comment'))

    def test_shell_structures_and_expansion_are_rejected_without_execution(self):
        for text in ('LOGINTERVAL=$(touch /synthetic-marker)', 'LOGINTERVAL=600; echo synthetic',
                     '. /synthetic-config', 'if true; then\nLOGINTERVAL=600\nfi',
                     'LOGINTERVAL=${INTERVAL}', 'LOGGENERATIONS=unknown', 'LOGINTERVAL=600 extra'):
            with patch('subprocess.Popen', side_effect=AssertionError('must not execute')):
                with self.assertRaises(ValueError):
                    atop_defaults(text)


class PreservationTests(unittest.TestCase):
    def test_cli_explicit_check_is_structured_read_only_and_does_not_replay_atop(self):
        sources, runner, output = SyntheticSources(), SyntheticRunner(), io.StringIO()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            self.assertEqual(0, main(['check', '--history', '--json'], sources=sources, runner=runner, stdout=output))
        data = json.loads(output.getvalue())
        observations = {item['key']: item for item in data['observations']}
        self.assertEqual('persistent', observations['journal.config.storage']['value'])
        self.assertEqual('unknown', observations['journal.config.storage']['state'])
        self.assertEqual(600, observations['atop.config.interval']['value'])
        self.assertTrue(observations['atop.config.interval']['recommendations'])
        self.assertEqual(2, observations['atop.recording_inventory']['value']['files'])
        self.assertIn(Command.JOURNAL_CONFIG, runner.calls)

    def test_ordinary_check_avoids_deep_config_collection(self):
        runner = SyntheticRunner()
        main(['check', '--json'], sources=SyntheticSources(), runner=runner, stdout=io.StringIO())
        self.assertNotIn(Command.JOURNAL_CONFIG, runner.calls)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['status', '--history'])

    def test_unavailable_journal_config_does_not_hide_other_preservation_evidence(self):
        runner = SyntheticRunner()
        runner.results[Command.JOURNAL_CONFIG] = Result('timeout')
        items = {item.key: item for item in assess(SyntheticSources(), runner)}
        self.assertEqual('unavailable', items['journal.config'].state)
        self.assertEqual(2, items['atop.recording_inventory'].value['files'])

    def test_volatile_configuration_is_warning_without_claiming_runtime_state(self):
        runner = SyntheticRunner()
        runner.results[Command.JOURNAL_CONFIG] = Result('completed', '[Journal]\nStorage=volatile', 0)
        item = next(item for item in assess(SyntheticSources(), runner) if item.key == 'journal.config.storage')
        self.assertEqual('warning', item.state)
        self.assertIn('running state remains unverified', item.explanation)

    def test_text_distinguishes_unknown_configuration_from_unavailable_source(self):
        runner = SyntheticRunner()
        runner.results[Command.JOURNAL_CONFIG] = Result('completed', '[Journal]\nStorage=unsupported', 0)
        output = io.StringIO()
        main(['check', '--history'], sources=SyntheticSources(), runner=runner, stdout=output)
        self.assertIn('[UNKNOWN] journal.config.storage: unknown mode', output.getvalue())
        self.assertIn('Final assignment uses an unsupported expression', output.getvalue())
        self.assertIn('No explicit assignment observed', output.getvalue())
        runner.results[Command.JOURNAL_CONFIG] = Result('missing')
        output = io.StringIO()
        main(['check', '--history'], sources=SyntheticSources(), runner=runner, stdout=output)
        self.assertIn('[UNAVAILABLE] journal.config: unavailable', output.getvalue())

    def test_raw_config_payload_and_custom_paths_are_not_reported(self):
        sources, runner = SyntheticSources(), SyntheticRunner()
        marker = 'synthetic-private-value'
        sources.values['/etc/default/atop'] = 'LOGPATH=/custom/' + marker + '\nSITE_LABEL=' + marker
        runner.results[Command.JOURNAL_CONFIG] = Result('completed', '[Journal]\nStorage=' + marker, 0)
        output = io.StringIO()
        main(['check', '--history', '--json'], sources=sources, runner=runner, stdout=output)
        self.assertNotIn(marker, output.getvalue())
        self.assertNotIn('/custom/', output.getvalue())


class MetadataInventoryTests(unittest.TestCase):
    def entry(self, name, *, size=100, uid=0, mode=stat.S_IFREG | 0o640):
        return SimpleNamespace(name=name, stat=lambda **kwargs: SimpleNamespace(st_size=size, st_uid=uid, st_mode=mode))

    def inventory(self, entries):
        with patch('faultlens.recordings.open_log_directory', return_value=14), patch('faultlens.linux.os.close') as close, patch(
                'faultlens.linux.os.scandir', return_value=contextlib.nullcontext(iter(entries))):
            result = LinuxSources().recording_inventory()
        close.assert_called_once_with(14)
        return result

    def test_inventory_reports_only_bounded_protected_file_metadata(self):
        items = [self.entry('atop_20260101'), self.entry('atop_20260102', size=0),
                 self.entry('atop_20260103', size=256*1024*1024+1),
                 self.entry('atop_20260104', mode=stat.S_IFLNK | 0o777),
                 self.entry('atop_20260105.gz'), self.entry('atop_20260230'), self.entry('private-unrelated-name')]
        value = self.inventory(items)
        self.assertEqual(3, value['files'])
        self.assertEqual(1, value['empty_files'])
        self.assertEqual(1, value['oversized_files'])
        self.assertEqual(1, value['unsafe_entries'])
        self.assertEqual(2, value['unsupported_entries'])
        self.assertEqual('20260101', value['oldest_date'])
        self.assertNotIn('private-unrelated-name', json.dumps(value))

    def test_enumeration_and_missing_permissions_do_not_produce_partial_success(self):
        with patch('faultlens.recordings.open_log_directory', return_value=14), patch('faultlens.linux.os.close') as close, patch(
                'faultlens.linux.os.scandir', return_value=contextlib.nullcontext(iter([self.entry('unrelated')] * 513))):
            with self.assertRaises(ValueError):
                LinuxSources().recording_inventory()
        close.assert_called_once_with(14)
        with patch('faultlens.recordings.open_log_directory', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                LinuxSources().log_filesystem('journal')
