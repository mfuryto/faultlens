"""Invented crash contents and temporary files; no real pstore evidence."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from faultlens import pstore, pstore_archive
from faultlens.cli import main
from tests.test_incidents import JournalRunner


def original_bytes(record):
    content = record['content']
    return content['value'].encode('utf-8') if content['encoding'] == 'utf-8' else base64.b64decode(content['value'], validate=True)


@contextlib.contextmanager
def source(root):
    original_stat = os.fstat
    descriptors = []
    def open_root(*args):
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(descriptor)
        return descriptor
    def metadata(descriptor):
        value = original_stat(descriptor)
        return SimpleNamespace(st_uid=0, st_gid=123, st_mode=value.st_mode, st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns,
            st_ino=value.st_ino, st_dev=value.st_dev)
    with patch('faultlens.pstore.open_directory', side_effect=open_root), patch('faultlens.pstore.os.fstat', side_effect=metadata):
        yield
    for descriptor in descriptors:
        with unittest.TestCase().assertRaises(OSError):
            original_stat(descriptor)


class PstoreAdministratorTests(unittest.TestCase):
    def write(self, root, relative, payload):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in (target.parent, *target.parent.parents):
            if parent == root:
                break
            parent.chmod(0o700)
        target.write_bytes(payload)
        target.chmod(0o600)
        return target

    def test_native_live_names_metadata_and_original_content_are_available_locally(self):
        payload = b'Kernel panic - not syncing: synthetic-task user=operator peer=192.0.2.8\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self.write(root, 'dmesg-ramoops-1', payload)
            metadata = target.stat()
            with source(root):
                data = pstore.analyze()
        record, = data['records']
        self.assertEqual('available', data['state'])
        self.assertEqual('/sys/fs/pstore', data['source_root'])
        self.assertEqual('dmesg-ramoops-1', record['relative_path'])
        self.assertEqual(0, record['metadata']['uid'])
        self.assertEqual(123, record['metadata']['gid'])
        self.assertEqual('0600', record['metadata']['mode_octal'])
        self.assertEqual(metadata.st_mtime_ns, record['metadata']['mtime_ns'])
        self.assertEqual(metadata.st_ino, record['metadata']['inode'])
        self.assertEqual(len(payload), record['metadata']['observed_size_bytes'])
        self.assertEqual(payload, original_bytes(record))
        self.assertEqual([1], record['panic_signature_lines'])
        self.assertEqual('unverified', data['boot_identity'])
        self.assertEqual('Unknown', data['root_cause'])

    def test_archive_retains_numeric_relative_path_without_time_or_boot_inference(self):
        payload = b'synthetic archive context\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, '100/200/dmesg-erst-3', payload)
            with source(root):
                data = pstore_archive.analyze()
        record, = data['records']
        self.assertEqual('/var/lib/systemd/pstore', data['source_root'])
        self.assertEqual('100/200/dmesg-erst-3', record['relative_path'])
        self.assertEqual(payload, original_bytes(record))
        self.assertEqual('unverified', data['boot_identity'])
        self.assertEqual('Unknown', record['confidence'])

    def test_nontext_and_structure_limited_data_are_lossless_without_signature_claims(self):
        for payload in (b'\xff\x00\x1b', b'Kernel panic - not syncing: synthetic\x00',
                        b'x'*4097, b'\n'*4097, b'\x1b'*8192):
            result = pstore.analyze(lambda: ([payload], 0))
            record, = result['records']
            self.assertEqual('available', result['state'])
            self.assertEqual('unavailable', result['analysis_state'])
            self.assertEqual([], record['panic_signature_lines'])
            self.assertEqual('Unknown', record['confidence'])
            self.assertEqual(payload, original_bytes(record))
            self.assertIsNone(record['metadata'])
            self.assertIsNone(record['relative_path'])

    def test_binary_file_does_not_hide_valid_sibling_evidence_or_fabricate_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, 'dmesg-ramoops-1', b'Kernel panic - not syncing: synthetic\n')
            self.write(root, 'dmesg-ramoops-2', b'\xff\x00')
            with source(root):
                result = pstore_archive.analyze()
        self.assertEqual('available', result['state'])
        self.assertEqual('partial', result['analysis_state'])
        self.assertEqual([1], result['records'][0]['panic_signature_lines'])
        self.assertEqual(b'\xff\x00', original_bytes(result['records'][1]))

    def test_file_trust_failure_still_discards_the_entire_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, 'dmesg-ramoops-1', b'Kernel panic - not syncing: synthetic\n')
            target = self.write(root, 'dmesg-ramoops-2', b'synthetic')
            target.chmod(0o666)
            with source(root):
                result = pstore.analyze()
        self.assertEqual('unavailable', result['state'])
        self.assertEqual([], result['records'])

    def test_cli_full_views_do_not_mask_values_and_escape_terminal_controls(self):
        payload = b'Kernel panic - not syncing: synthetic-user 192.0.2.8\x1b]52;c;payload\x07\n'
        collector = lambda: ([pstore.Record(payload, 'dmesg-ramoops-1', {'uid':0})], 0)
        for flags in (['--show-evidence'], ['--json']):
            output = io.StringIO()
            main(['diagnose', '--pstore', '--pstore-archive']+flags, runner=JournalRunner(),
                 pstore_collector=collector, pstore_archive_collector=collector, stdout=output)
            rendered = output.getvalue()
            self.assertIn('synthetic-user', rendered)
            self.assertIn('192.0.2.8', rendered)
            self.assertIn('dmesg-ramoops-1', rendered)
            self.assertNotIn('\x1b', rendered)
            self.assertIn('\\u001b', rendered)
            if flags == ['--json']:
                data = json.loads(rendered)
                self.assertEqual(payload, original_bytes(data['pstore']['records'][0]))
                self.assertEqual(payload, original_bytes(data['pstore_archive']['records'][0]))

    def test_source_selector_never_labels_a_live_read_as_an_archive(self):
        with patch('faultlens.pstore.collect', side_effect=AssertionError('must not read live')), patch(
                'faultlens.pstore_archive.collect', return_value=([b'synthetic archive'], 0)) as archive:
            result = pstore.analyze(source='archive')
        archive.assert_called_once_with()
        self.assertEqual('systemd-pstore-archive', result['source'])
        self.assertEqual('/var/lib/systemd/pstore', result['source_root'])

    def test_size_file_count_and_total_limits_remain_source_failures(self):
        for values in ([b'x'*(pstore.MAX_FILE_BYTES+1)], [b'x']*9, [b'x'*131072]*5):
            result = pstore.analyze(lambda: (values, 0))
            self.assertEqual('unavailable', result['state'])
            self.assertEqual([], result['records'])
