"""Synthetic archive layouts; no live host archive or crash payload is read."""
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

from faultlens import pstore, pstore_archive
from faultlens.cli import main
from tests.test_incidents import JournalRunner


class ArchiveTests(unittest.TestCase):
    @contextlib.contextmanager
    def snapshot(self, root):
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        original_stat = os.fstat
        def metadata(fd):
            value = original_stat(fd)
            return SimpleNamespace(st_uid=0, st_mode=value.st_mode, st_size=value.st_size,
                                   st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns)
        with patch('faultlens.pstore.open_directory', return_value=descriptor), patch('faultlens.pstore.os.fstat', side_effect=metadata):
            yield
        # collect owns the descriptor, including all exceptional exits.
        with self.assertRaises(OSError):
            original_stat(descriptor)

    def write(self, root, path, text='Kernel panic - not syncing: synthetic-private-payload\n'):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in (target.parent, *target.parent.parents):
            if parent == root:
                break
            parent.chmod(0o700)
        target.write_text(text)
        target.chmod(0o600)
        return target

    def test_flat_erst_and_two_level_efi_layouts_use_raw_records_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in ('dmesg-ramoops-0', '100/dmesg-erst-100', '200/001/dmesg-efi_pstore-20001001'):
                self.write(root, path)
            self.write(root, '200/001/dmesg.txt', 'reconstructed-duplicate-must-not-read')
            self.write(root, '200/001/dmesg-efi_pstore-20002001.enc.z', 'compressed-must-not-read')
            self.write(root, 'unrelated/private', 'unknown-subtree-must-not-read')
            with self.snapshot(root):
                data = pstore_archive.analyze()
        self.assertEqual('available', data['state'])
        self.assertEqual(3, len(data['records']))
        self.assertEqual(3, data['excluded_entries'])
        self.assertTrue(all(item['panic_signature_lines'] == [1] for item in data['records']))
        self.assertEqual('systemd-pstore-archive', data['source'])
        self.assertTrue(all('synthetic-private-payload' in record['content']['value'] for record in data['records']))
        self.assertIn('200/001/dmesg-efi_pstore-20001001', [record['relative_path'] for record in data['records']])
        self.assertEqual('unverified', data['boot_identity'])
        self.assertEqual('Unknown', data['root_cause'])

    def test_empty_archive_and_unsupported_only_do_not_establish_absence_of_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, 'dmesg.txt')
            with self.snapshot(root):
                data = pstore_archive.analyze()
        self.assertEqual('no_supported_records_visible', data['reason'])
        self.assertEqual(1, data['excluded_entries'])
        self.assertIn('does not exclude a crash', ' '.join(data['limitations']))

    def test_numeric_symlink_fifo_and_unsafe_directories_fail_closed(self):
        for kind in ('symlink', 'fifo', 'writable'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.write(root, 'dmesg-ramoops-0')
                if kind == 'symlink':
                    (root / '100').symlink_to(root, target_is_directory=True)
                elif kind == 'fifo':
                    os.mkfifo(root / '100')
                else:
                    (root / '100').mkdir(mode=0o700)
                    (root / '100').chmod(0o777)
                with self.snapshot(root):
                    data = pstore_archive.analyze()
            self.assertEqual('unavailable', data['state'])
            self.assertEqual([], data['records'])

    def test_unsafe_supported_files_and_partial_failure_discard_all_findings(self):
        for kind in ('symlink', 'writable', 'oversized', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.write(root, 'dmesg-ramoops-0')
                path = root / 'dmesg-ramoops-1'
                if kind == 'symlink':
                    path.symlink_to(root / 'dmesg-ramoops-0')
                elif kind == 'fifo':
                    os.mkfifo(path)
                else:
                    self.write(root, path.name, 'x' * (131073 if kind == 'oversized' else 1))
                    if kind == 'writable':
                        path.chmod(0o666)
                    elif kind == 'binary':
                        path.write_bytes(b'\xff')
                with self.snapshot(root):
                    data = pstore_archive.analyze()
            self.assertEqual('unavailable', data['state'])
            self.assertEqual([], data['records'])

    def test_global_entry_file_byte_depth_and_directory_limits(self):
        for limit in ('entries', 'files', 'bytes', 'depth', 'directories'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if limit == 'entries':
                    (root / '100').mkdir(mode=0o700)
                    for index in range(64):
                        self.write(root, '100/unknown-' + str(index), '')
                elif limit in ('files', 'bytes'):
                    for index in range(9 if limit == 'files' else 5):
                        self.write(root, 'dmesg-ramoops-' + str(index), 'x' * (131072 if limit == 'bytes' else 1))
                elif limit == 'depth':
                    self.write(root, '100/200/300/unknown', '')
                else:
                    for index in range(16):
                        (root / str(index)).mkdir(mode=0o700)
                with self.snapshot(root):
                    data = pstore_archive.analyze()
            self.assertEqual('unavailable', data['state'])
            self.assertEqual([], data['records'])

    def test_missing_and_denied_archive_have_fixed_reasons(self):
        for failure, reason in ((PermissionError, 'access_denied'), (FileNotFoundError, 'source_absent_or_changed')):
            with patch('faultlens.pstore.open_directory', side_effect=failure):
                data = pstore_archive.analyze()
            self.assertEqual(reason, data['reason'])
            self.assertNotIn('Live /sys/fs/pstore only', ' '.join(data['limitations']))

    def test_fixed_archive_path_and_no_user_paths(self):
        directory = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        with patch('faultlens.pstore.os.open', side_effect=[10, 11, 12, 13, 14]) as opened, patch(
                'faultlens.pstore.os.fstat', return_value=directory), patch('faultlens.pstore.os.close') as closed:
            self.assertEqual(14, pstore.open_directory('archive'))
        self.assertEqual(['/', 'var', 'lib', 'systemd', 'pstore'], [call.args[0] for call in opened.call_args_list])
        self.assertEqual([10, 11, 12, 13], [call.args[0] for call in closed.call_args_list])
        for call in opened.call_args_list:
            self.assertTrue(call.args[1] & os.O_NOFOLLOW)
            self.assertEqual(os.O_RDONLY, call.args[1] & os.O_ACCMODE)
        with patch('faultlens.pstore.os.open', side_effect=AssertionError('must not open')):
            with self.assertRaises(ValueError):
                pstore.open_directory('/arbitrary/private')

    def test_cli_sources_are_independently_opt_in_and_never_upgrade_boot_confidence(self):
        for json_mode in (True, False):
            output = io.StringIO()
            with patch('faultlens.pstore.collect', side_effect=PermissionError), patch('faultlens.pstore_archive.collect',
                    return_value=([b'Kernel panic - not syncing: synthetic'], 0)):
                main(['diagnose', '--boot', '-128', '--pstore', '--pstore-archive'] + (['--json'] if json_mode else ['--details']),
                     runner=JournalRunner(), stdout=output)
            if json_mode:
                data = json.loads(output.getvalue())
                self.assertEqual('unavailable', data['state'])
                self.assertEqual('unavailable', data['pstore']['state'])
                self.assertEqual('available', data['pstore_archive']['state'])
                self.assertEqual('Unknown', data['root_cause'])
            else:
                self.assertIn('Pstore archive: available', output.getvalue())
        with patch('faultlens.pstore_archive.collect', side_effect=AssertionError('must not read')):
            main(['diagnose', '--pstore', '--json'], runner=JournalRunner(), stdout=io.StringIO(),
                 pstore_collector=lambda: ([], 0))
        with patch('faultlens.pstore.collect', side_effect=AssertionError('must not read')):
            main(['diagnose', '--pstore-archive', '--json'], runner=JournalRunner(), stdout=io.StringIO(),
                 pstore_archive_collector=lambda: ([], 0))
        for command in ('status', 'check', 'history'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([command, '--pstore-archive'])
