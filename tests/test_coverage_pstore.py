"""Invented coverage and crash data; no host pstore or recordings are collected."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.coverage import date_gaps, sample_coverage
from faultlens.atop import samples
from faultlens import pstore
from faultlens.linux import LinuxSources
from tests.test_atop import sample, EPOCH, AtopRunner
from tests.test_incidents import JournalRunner


class CoverageTests(unittest.TestCase):
    def test_date_ranges_are_internal_only_sorted_deduplicated_and_leap_aware(self):
        data = date_gaps(['20260302', '20260227', '20260227'])
        self.assertEqual([{'first_missing_date': '20260228', 'last_missing_date': '20260301',
                           'missing_days': 2}], data['date_ranges'])
        self.assertEqual(2, data['missing_filename_days'])
        self.assertEqual(1, date_gaps(['20240228', '20240301'])['missing_filename_days'])
        for dates in ([], ['20260101'], ['20260101', '20260102']):
            self.assertEqual(0, date_gaps(dates)['missing_filename_days'])
        with self.assertRaises(ValueError):
            date_gaps(['20260101'] * 513)

    def test_inventory_gap_metadata_uses_complete_enumeration(self):
        metadata = SimpleNamespace(st_size=100, st_uid=0, st_mode=stat.S_IFREG | 0o640)
        entries = [SimpleNamespace(name='atop_' + date, stat=lambda **kwargs: metadata)
                   for date in ('20260101', '20260104')]
        with patch('faultlens.recordings.open_log_directory', return_value=14), patch('faultlens.linux.os.close'), patch(
                'faultlens.linux.os.scandir', return_value=contextlib.nullcontext(iter(entries))):
            data = LinuxSources().recording_inventory()
        self.assertEqual(2, data['filename_coverage']['missing_filename_days'])

    def test_interval_coverage_uses_current_reported_period_not_expected_schedule(self):
        values = samples(sample() + sample(EPOCH + 90, period=30) + sample(EPOCH + 120, period=30))
        data = sample_coverage(values)
        self.assertEqual(1, len(data['possible_gaps']))
        self.assertEqual(30, data['possible_gaps'][0]['duration_s'])
        self.assertEqual('Possible', data['possible_gaps'][0]['confidence'])
        self.assertEqual([], sample_coverage(samples(sample() + sample(EPOCH + 90, period=60)))['possible_gaps'])

    def test_resets_overlaps_and_single_samples_do_not_claim_gaps_or_complete_history(self):
        values = samples(sample() + sample(EPOCH + 90, period=60, reset=True) + sample(EPOCH + 120))
        data = sample_coverage(values)
        self.assertEqual([], data['possible_gaps'])
        self.assertEqual(1, data['reset_samples'])
        self.assertEqual(1, sample_coverage(samples(sample() + sample(EPOCH + 40, period=30)))['overlapping_intervals'])
        self.assertEqual([], sample_coverage(samples(sample()))['possible_gaps'])
        self.assertIn('No gaps found does not prove', data['limitations'][1])

    def test_cli_reports_sample_gaps_without_promoting_root_cause(self):
        output = io.StringIO()
        runner = AtopRunner(text=sample() + sample(EPOCH + 90))
        main(['diagnose', '--atop-date', '20260101', '--json'], runner=runner, stdout=output)
        data = json.loads(output.getvalue())
        self.assertEqual(1, len(data['atop']['coverage']['possible_gaps']))
        self.assertEqual('Unknown', data['root_cause'])


class PstoreAnalysisTests(unittest.TestCase):
    def test_signatures_keep_local_original_content_without_time_or_boot_attribution(self):
        secret = 'synthetic-private-payload'
        payload = ('Panic#1 Part1\n<0>[   12.345] Kernel panic - not syncing: ' + secret + '\x1b]52;c;x\x07\n').encode()
        data = pstore.analyze(lambda: ([payload], 2))
        self.assertEqual('available', data['state'])
        self.assertEqual([2], data['records'][0]['panic_signature_lines'])
        self.assertEqual('Possible', data['records'][0]['confidence'])
        self.assertEqual(64, len(data['records'][0]['sha256']))
        self.assertEqual(2, data['excluded_entries'])
        self.assertIn(secret, data['records'][0]['content']['value'])
        self.assertIn('52;c', data['records'][0]['content']['value'])
        self.assertNotIn('\x1b', json.dumps(data))
        self.assertEqual('unverified', data['boot_identity'])
        self.assertEqual('Unknown', data['root_cause'])

    def test_empty_and_nonmatching_records_do_not_exclude_crashes(self):
        empty = pstore.analyze(lambda: ([], 0))
        self.assertEqual('no_supported_records_visible', empty['reason'])
        self.assertIn('does not exclude a crash', ' '.join(empty['limitations']))
        data = pstore.analyze(lambda: ([b'user says Kernel panic - not syncing: synthetic\n'], 0))
        self.assertEqual([], data['records'][0]['panic_signature_lines'])

    def test_denied_missing_binary_oversized_and_malformed_sources_are_explicit(self):
        for failure, reason in ((PermissionError, 'access_denied'), (FileNotFoundError, 'source_absent_or_changed')):
            with patch('faultlens.pstore.collect', side_effect=failure):
                self.assertEqual(reason, pstore.analyze()['reason'])
        for records in ([b'x' * (pstore.MAX_FILE_BYTES + 1)], [b'x'] * 9, [b'x' * 131072] * 5):
            data = pstore.analyze(lambda: (records, 0))
            self.assertEqual('unavailable', data['state'])
            self.assertEqual([], data['records'])

    def test_cli_is_opt_in_and_runs_independently_of_missing_selected_boot(self):
        with patch('faultlens.pstore.collect', side_effect=AssertionError('must not read')):
            main(['diagnose', '--json'], runner=JournalRunner(), stdout=io.StringIO())
        for json_mode in (True, False):
            output = io.StringIO()
            with patch('faultlens.pstore.collect', return_value=([b'Kernel panic - not syncing: synthetic'], 0)):
                main(['diagnose', '--boot', '-128', '--pstore'] + (['--json'] if json_mode else []),
                     runner=JournalRunner(), stdout=output)
            if json_mode:
                data = json.loads(output.getvalue())
                self.assertEqual('unavailable', data['state'])
                self.assertEqual('available', data['pstore']['state'])
                self.assertEqual('Unknown', data['root_cause'])
            else:
                self.assertIn('Pstore: available', output.getvalue())
        for command in ('check', 'history', 'status'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([command, '--pstore'])


class PstoreBoundaryTests(unittest.TestCase):
    def test_fixed_path_walk_rejects_untrusted_ancestors_and_closes_descriptors(self):
        directory = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        with patch('faultlens.pstore.os.open', side_effect=[10, 11, 12, 13]) as opened, patch(
                'faultlens.pstore.os.fstat', return_value=directory), patch('faultlens.pstore.os.close') as closed:
            self.assertEqual(13, pstore.open_directory())
        self.assertEqual(['/', 'sys', 'fs', 'pstore'], [call.args[0] for call in opened.call_args_list])
        self.assertTrue(all(call.args[1] & os.O_NOFOLLOW for call in opened.call_args_list))
        self.assertEqual([10, 11, 12], [call.args[0] for call in closed.call_args_list])
        with patch('faultlens.pstore.os.open', return_value=10), patch('faultlens.pstore.os.fstat',
                return_value=SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o755)), patch('faultlens.pstore.os.close') as closed:
            with self.assertRaises(ValueError):
                pstore.open_directory()
        closed.assert_called_once_with(10)

    def test_descriptor_reader_is_bounded_nonblocking_and_never_follows_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'dmesg-ramoops-0').write_bytes(b'Kernel panic - not syncing: synthetic')
            (root / 'dmesg-ramoops-0').chmod(0o600)
            (root / 'dmesg-ramoops-1').symlink_to(root / 'dmesg-ramoops-0')
            os.mkfifo(root / 'dmesg-ramoops-2')
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            native_stat = os.fstat
            def metadata(fd):
                value = native_stat(fd)
                return SimpleNamespace(st_uid=0, st_mode=value.st_mode, st_size=value.st_size,
                                       st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns)
            try:
                with patch('faultlens.pstore.os.fstat', side_effect=metadata):
                    self.assertIn(b'Kernel panic', pstore.read_record(descriptor, 'dmesg-ramoops-0'))
                    for name in ('dmesg-ramoops-1', 'dmesg-ramoops-2', '../private', 'unknown'):
                        with self.assertRaises((OSError, ValueError)):
                            pstore.read_record(descriptor, name)
            finally:
                os.close(descriptor)

    def test_record_metadata_changes_and_unsafe_permissions_are_rejected(self):
        def metadata(**changes):
            values = dict(st_uid=0, st_mode=stat.S_IFREG | 0o600, st_size=10, st_mtime_ns=1, st_ctime_ns=1)
            values.update(changes)
            return SimpleNamespace(**values)
        for meta in (metadata(st_uid=1000), metadata(st_mode=stat.S_IFREG | 0o666),
                     metadata(st_mode=stat.S_IFIFO | 0o600), metadata(st_size=131073)):
            with patch('faultlens.pstore.os.open', return_value=14), patch('faultlens.pstore.os.fstat', return_value=meta), patch(
                    'faultlens.pstore.os.close') as closed, patch('faultlens.pstore.os.read', side_effect=AssertionError('must not read')):
                with self.assertRaises(ValueError):
                    pstore.read_record(13, 'dmesg-ramoops-0')
            closed.assert_called_once_with(14)
        with patch('faultlens.pstore.os.open', return_value=14), patch('faultlens.pstore.os.fstat',
                side_effect=[metadata(), metadata(st_mtime_ns=2)]), patch('faultlens.pstore.os.read', return_value=b''), patch('faultlens.pstore.os.close'):
            with self.assertRaises(ValueError):
                pstore.read_record(13, 'dmesg-ramoops-0')

    def test_read_cap_applies_even_when_file_size_is_zero(self):
        metadata = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600, st_size=0,
                                   st_mtime_ns=1, st_ctime_ns=1)
        for chunks, valid in (([b'Kernel panic - not syncing: synthetic', b''], True),
                              ([b'x' * 8192] * 16 + [b'x'], False)):
            with patch('faultlens.pstore.os.open', return_value=14), patch('faultlens.pstore.os.fstat', return_value=metadata), patch(
                    'faultlens.pstore.os.read', side_effect=chunks), patch('faultlens.pstore.os.close') as closed:
                if valid:
                    self.assertIn(b'Kernel panic', pstore.read_record(13, 'dmesg-ramoops-0'))
                else:
                    with self.assertRaises(ValueError):
                        pstore.read_record(13, 'dmesg-ramoops-0')
            closed.assert_called_once_with(14)

    def test_collect_sorts_records_and_enforces_aggregate_limit(self):
        names = ['dmesg-ramoops-' + str(i) for i in reversed(range(5))]
        for size, valid in ((10, True), (131072, False)):
            with patch('faultlens.pstore.open_directory', return_value=13), patch('faultlens.pstore.os.close') as closed, patch(
                    'faultlens.pstore.os.scandir', return_value=contextlib.nullcontext(iter(SimpleNamespace(name=name) for name in names))), patch(
                    'faultlens.pstore.read_record', return_value=b'x' * size) as reader:
                if valid:
                    records, excluded = pstore.collect()
                    self.assertEqual(5, len(records))
                    self.assertEqual(0, excluded)
                    self.assertEqual(sorted(names), [call.args[1] for call in reader.call_args_list])
                else:
                    with self.assertRaises(ValueError):
                        pstore.collect()
            closed.assert_called_once_with(13)

    def test_enumeration_caps_fail_closed_and_unknown_names_are_not_opened(self):
        for names in (['unrelated'] * 65, ['dmesg-ramoops-' + str(i) for i in range(9)]):
            with patch('faultlens.pstore.open_directory', return_value=13), patch('faultlens.pstore.os.close') as closed, patch(
                    'faultlens.pstore.os.scandir', return_value=contextlib.nullcontext(iter(SimpleNamespace(name=name) for name in names))), patch(
                    'faultlens.pstore.read_record', side_effect=AssertionError('must not read')):
                with self.assertRaises(ValueError):
                    pstore.collect()
            closed.assert_called_once_with(13)
        with patch('faultlens.pstore.open_directory', return_value=13), patch('faultlens.pstore.os.close'), patch(
                'faultlens.pstore.os.scandir', return_value=contextlib.nullcontext(iter([SimpleNamespace(name='private-unrelated')]))), patch(
                'faultlens.pstore.read_record', side_effect=AssertionError('must not read')):
            self.assertEqual(([], 1), pstore.collect())
