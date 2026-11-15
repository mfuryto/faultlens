"""Read only bounded raw records in the fixed systemd pstore archive."""
import os
import re
from dataclasses import replace

from . import pstore
from .recordings import trusted_metadata

NUMERIC = re.compile(r'[0-9]{1,20}')
MAX_DIRECTORIES = 16
MAX_DEPTH = 2
LIMITATIONS = [
    'Fixed /var/lib/systemd/pstore archive only; custom paths, journal-only archives and backend state are not inspected.',
    'Only raw supported record names within two numeric directory levels are read; reconstructed dmesg.txt and compressed/other entries are excluded.',
    'Record fragments are not reassembled; split signatures can be missed. No match or empty archive does not exclude a crash.',
    'Archive directory names and file times are not interpreted as event times or boot identity.',
    'Matching content hashes across live/archive or repeated records do not provide independent corroboration.',
    'Signature observations do not establish authenticity, root cause or association with the selected boot.',
    'Root/kernel compromise can falsify evidence. Collection is bounded and non-atomic; filesystem calls have no hard deadline.',
]


def collect():
    root = pstore.open_directory('archive')
    records, total, entries, directories, excluded = [], 0, 0, 1, 0

    def walk(descriptor, depth, prefix=()):
        nonlocal total, entries, directories, excluded
        names = []
        with os.scandir(descriptor) as listing:
            for entry in listing:
                entries += 1
                if entries > pstore.MAX_ENTRIES:
                    raise ValueError('Archive enumeration limit')
                names.append(entry.name)
        for name in sorted(names):
            if pstore.NAME.fullmatch(name):
                if len(records) >= pstore.MAX_FILES:
                    raise ValueError('Archive file limit')
                data = pstore.read_record(descriptor, name, include_metadata=True)
                total += len(pstore.record_bytes(data))
                if total > pstore.MAX_TOTAL_BYTES:
                    raise ValueError('Archive aggregate limit')
                records.append(replace(data, relative_path='/'.join((*prefix, name))) if isinstance(data, pstore.Record) else data)
            elif NUMERIC.fullmatch(name):
                if depth >= MAX_DEPTH or directories >= MAX_DIRECTORIES:
                    raise ValueError('Archive directory limit')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                try:
                    trusted_metadata(os.fstat(child), directory=True)
                    directories += 1
                    walk(child, depth + 1, (*prefix, name))
                finally:
                    os.close(child)
            else:
                excluded += 1
    try:
        walk(root, 0)
        return records, excluded
    finally:
        os.close(root)


def analyze(collector=None):
    result = pstore.analyze(collector or collect, source='archive')
    result.update(source='systemd-pstore-archive', limitations=list(LIMITATIONS),
                  recommendations=['Review archive policy and permissions locally; Faultlens does not change them or read arbitrary paths.'])
    return result
