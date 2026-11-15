"""Opt-in bounded pstore snapshots; never erase, mount, archive or attribute a boot."""
import hashlib
import base64
import json
from dataclasses import dataclass
import os
import re
import stat

from .recordings import trusted_metadata

MAX_ENTRIES = 64
MAX_FILES = 8
MAX_FILE_BYTES = 131072
MAX_TOTAL_BYTES = 524288
NAME = re.compile(r'(?:dmesg-(?:ramoops|efi|efi_pstore|erst|pstore-blk)|console-ramoops)-[0-9]{1,20}')
PANIC = re.compile(r'^(?:<[0-7]>)?(?:\[\s*[0-9]{1,12}(?:\.[0-9]{1,9})?\]\s*)?Kernel panic - not syncing:')
LIMITATIONS = [
    'Live /sys/fs/pstore only; firmware/backend support, mount state and archived records are not verified.',
    'Empty or absent pstore does not exclude a crash; another service may have archived or erased records.',
    'Signature observations do not establish authenticity, root cause, event time or association with the selected boot.',
    'Root/kernel compromise can falsify local evidence. Collection is a non-atomic snapshot.',
]


@dataclass(frozen=True)
class Record:
    data: bytes
    relative_path: str | None = None
    metadata: dict | None = None


def record_bytes(record):
    data = record.data if isinstance(record, Record) else record
    if not isinstance(data, bytes):
        raise ValueError('Unsupported pstore snapshot representation')
    return data


def open_directory(source='live'):
    roots = {'live': ('sys', 'fs', 'pstore'), 'archive': ('var', 'lib', 'systemd', 'pstore')}
    if source not in roots:
        raise ValueError('Unsupported pstore source')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        trusted_metadata(os.fstat(descriptor), directory=True)
        for name in roots[source]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            trusted_metadata(os.fstat(descriptor), directory=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_record(directory, name, *, include_metadata=False):
    if not NAME.fullmatch(name):
        raise ValueError('Unsupported pstore filename')
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 0 <= before.st_size <= MAX_FILE_BYTES):
            raise ValueError('Unsafe pstore record')
        data = bytearray()
        while len(data) <= MAX_FILE_BYTES:
            chunk = os.read(descriptor, min(8192, MAX_FILE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if (len(data) > MAX_FILE_BYTES or
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('Oversized or changing pstore record')
        if not include_metadata:
            return bytes(data)
        return Record(bytes(data), name, {
            'uid': before.st_uid, 'gid': getattr(before, 'st_gid', None),
            'mode_octal': format(stat.S_IMODE(before.st_mode), '04o'),
            'observed_size_bytes': before.st_size,
            'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns,
            'inode': getattr(before, 'st_ino', None), 'device': getattr(before, 'st_dev', None)})
    finally:
        os.close(descriptor)


def collect():
    directory = open_directory()
    try:
        names, excluded = [], 0
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_ENTRIES:
                    raise ValueError('Pstore entry limit')
                if NAME.fullmatch(entry.name):
                    names.append(entry.name)
                    if len(names) > MAX_FILES:
                        raise ValueError('Pstore file limit')
                else:
                    excluded += 1
        records, total = [], 0
        for name in sorted(names):
            data = read_record(directory, name, include_metadata=True)
            total += len(record_bytes(data))
            if total > MAX_TOTAL_BYTES:
                raise ValueError('Pstore aggregate limit')
            records.append(data)
        return records, excluded
    finally:
        os.close(directory)


def analyze(collector=None, *, source='live'):
    if source not in {'live', 'archive'}:
        raise ValueError('Unsupported pstore source')
    if source == 'archive' and collector is None:
        from .pstore_archive import analyze as analyze_archive
        return analyze_archive()
    limitations = list(LIMITATIONS)
    if source == 'archive':
        limitations[0] = 'Fixed /var/lib/systemd/pstore archive only; custom locations are not inspected.'
    result = {'state': 'unavailable', 'records': [], 'excluded_entries': None,
              'source': 'pstore-live' if source == 'live' else 'systemd-pstore-archive',
              'source_root': '/sys/fs/pstore' if source == 'live' else '/var/lib/systemd/pstore',
              'analysis_state': 'unavailable',
              'root_cause': 'Unknown', 'boot_identity': 'unverified', 'limitations': limitations,
              'recommendations': ['Review local pstore archiving configuration and evidence access; Faultlens never elevates or deletes records.']}
    try:
        records, excluded = (collector or collect)()
        if len(records) > MAX_FILES or sum(len(record_bytes(record)) for record in records) > MAX_TOTAL_BYTES:
            raise ValueError('Pstore snapshot limit')
        normalized = []
        for index, record in enumerate(records):
            data = record_bytes(record)
            if len(data) > MAX_FILE_BYTES:
                raise ValueError('Pstore record limit')
            text, reason = None, None
            try:
                text = data.decode('utf-8', errors='strict')
            except UnicodeError:
                reason = 'non_utf8_content'
            if text is not None and '\x00' in text:
                reason = 'binary_nul_content'
            lines = text.splitlines() if text is not None and reason is None else []
            if reason is None and (len(lines) > 4096 or any(len(line) > 4096 for line in lines)):
                reason = 'text_analysis_structure_limit'
            signatures = [number for number, line in enumerate(lines, 1) if PANIC.match(line)] if reason is None else []
            # Lossless base64 also bounds the expansion of terminal-escaped text.
            encoded_text = json.dumps(text, ensure_ascii=True) if text is not None else None
            use_text = text is not None and '\x00' not in text and len(encoded_text)-2 <= 2*len(data)
            content = {'encoding': 'utf-8' if use_text else 'base64',
                       'encoding_reason': 'original_utf8' if use_text else 'binary_representation'
                                          if text is None or '\x00' in text else 'bounded_json_expansion',
                       'value': text if use_text else base64.b64encode(data).decode('ascii')}
            normalized.append({'record_index': index, 'sha256': hashlib.sha256(data).hexdigest(),
                               'bytes_examined': len(data), 'panic_signature_lines': signatures,
                               'confidence': 'Possible' if signatures else 'Unknown',
                               'relative_path': record.relative_path if isinstance(record, Record) else None,
                               'metadata': record.metadata if isinstance(record, Record) else None,
                               'content': content, 'analysis_state': 'available' if reason is None else 'unavailable',
                               'analysis_reason': reason})
        analyzed = sum(record['analysis_state'] == 'available' for record in normalized)
        result.update(state='available', records=normalized, excluded_entries=excluded,
                      analysis_state='not_applicable' if not normalized else 'available' if analyzed == len(normalized)
                                     else 'partial' if analyzed else 'unavailable',
                      reason='records_examined' if records else 'no_supported_records_visible')
    except PermissionError:
        result['reason'] = 'access_denied'
    except FileNotFoundError:
        result['reason'] = 'source_absent_or_changed'
    except (OSError, ValueError, UnicodeError):
        result['reason'] = 'unsafe_unsupported_or_incomplete_snapshot'
    return result
