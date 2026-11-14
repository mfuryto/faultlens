"""Opt-in bounded pstore snapshots; never erase, mount, archive or attribute a boot."""
import hashlib
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


def read_record(directory, name):
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
        return bytes(data)
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
            data = read_record(directory, name)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ValueError('Pstore aggregate limit')
            records.append(data)
        return records, excluded
    finally:
        os.close(directory)


def analyze(collector=None):
    result = {'state': 'unavailable', 'records': [], 'excluded_entries': None,
              'root_cause': 'Unknown', 'boot_identity': 'unverified', 'limitations': LIMITATIONS,
              'recommendations': ['Review local pstore archiving configuration and evidence access; Faultlens never elevates or deletes records.']}
    try:
        records, excluded = (collector or collect)()
        if len(records) > MAX_FILES or sum(len(data) for data in records) > MAX_TOTAL_BYTES:
            raise ValueError('Pstore snapshot limit')
        normalized = []
        for index, data in enumerate(records):
            if len(data) > MAX_FILE_BYTES:
                raise ValueError('Pstore record limit')
            text = data.decode('utf-8', errors='strict')
            if '\x00' in text:
                raise ValueError('Unsupported binary pstore record')
            lines = text.splitlines()
            if len(lines) > 4096 or any(len(line) > 4096 for line in lines):
                raise ValueError('Pstore text structure limit')
            signatures = [number for number, line in enumerate(lines, 1) if PANIC.match(line)]
            normalized.append({'record_index': index, 'sha256': hashlib.sha256(data).hexdigest(),
                               'bytes_examined': len(data), 'panic_signature_lines': signatures,
                               'confidence': 'Possible' if signatures else 'Unknown'})
        result.update(state='available', records=normalized, excluded_entries=excluded,
                      reason='records_examined' if records else 'no_supported_records_visible')
    except PermissionError:
        result['reason'] = 'access_denied'
    except FileNotFoundError:
        result['reason'] = 'source_absent_or_changed'
    except (OSError, ValueError, UnicodeError):
        result['reason'] = 'unsafe_unsupported_or_incomplete_snapshot'
    return result
