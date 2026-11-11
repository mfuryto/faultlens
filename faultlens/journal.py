"""Strict, bounded journal normalization; raw messages are retained in memory only."""
from dataclasses import dataclass
import json
import hashlib
import re

BOOT_ID = re.compile(r'[0-9a-f]{32}\Z')
CURSOR = re.compile(r'[A-Za-z0-9_=;:-]{1,1024}\Z')
MAX_RECORDS = 500
MAX_BYTES = 262144


@dataclass(frozen=True)
class Boot:
    index: int
    boot_id: str


@dataclass(frozen=True)
class Entry:
    boot_id: str
    realtime_us: int
    monotonic_us: int
    cursor: str | None
    transport: str
    pid: str
    comm: str
    message_id: str
    message: str | None

    def reference(self) -> dict:
        return {'source': 'systemd-journal', 'boot_id': self.boot_id,
                'realtime_us': self.realtime_us, 'monotonic_us': self.monotonic_us,
                'cursor_sha256': hashlib.sha256(self.cursor.encode()).hexdigest() if self.cursor else None}


def boots(text: str) -> list[Boot]:
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Boot listing exceeds limit')
    result, indices, identities = [], set(), set()
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 3 or not re.fullmatch(r'-?[0-9]{1,6}', fields[0]) or not BOOT_ID.fullmatch(fields[1]):
            raise ValueError('Malformed boot listing')
        index = int(fields[0])
        if index > 0 or index in indices or fields[1] in identities or len(result) >= 128:
            raise ValueError('Ambiguous or excessive boot listing')
        indices.add(index)
        identities.add(fields[1])
        result.append(Boot(index, fields[1]))
    return sorted(result, key=lambda item: item.index, reverse=True)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate journal field')
        value[key] = item
    return value


def timestamp(value, maximum):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,20}', value):
        raise ValueError('Invalid journal timestamp')
    value = int(value)
    if value > maximum:
        raise ValueError('Journal timestamp out of range')
    return value


def entries(text: str, boot_id: str) -> tuple[list[Entry], bool, int]:
    if not BOOT_ID.fullmatch(boot_id) or len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Invalid journal scope or size')
    result, seen = [], set()
    unsupported = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        if len(result) >= MAX_RECORDS + 1:
            raise ValueError('Too many journal records')
        try:
            item = json.loads(line, object_pairs_hook=unique_object)
        except (ValueError, RecursionError) as exc:
            raise ValueError('Invalid journal JSON') from exc
        if not isinstance(item, dict) or item.get('_BOOT_ID') != boot_id:
            raise ValueError('Journal record does not belong to selected boot')
        realtime = timestamp(item.get('__REALTIME_TIMESTAMP'), 253402300799999999)
        monotonic = timestamp(item.get('__MONOTONIC_TIMESTAMP'), 10**20 - 1)
        cursor = item.get('__CURSOR')
        if cursor is not None:
            if not isinstance(cursor, str) or not CURSOR.fullmatch(cursor) or cursor in seen:
                raise ValueError('Invalid or duplicate journal cursor')
            seen.add(cursor)
        for key in ('_TRANSPORT', '_PID', '_COMM', 'MESSAGE_ID'):
            if not isinstance(item.get(key, ''), str) or len(item.get(key, '')) > 128:
                raise ValueError('Invalid journal metadata')
        message = item.get('MESSAGE')
        if not isinstance(message, str) or len(message) > 8192:
            message = None
            unsupported += 1
        result.append(Entry(boot_id, realtime, monotonic, cursor, item.get('_TRANSPORT', ''),
                            item.get('_PID', ''), item.get('_COMM', ''), item.get('MESSAGE_ID', ''), message))
    # A monotonic boot-local timeline survives wall-clock steps. Stable ties preserve input order.
    result.sort(key=lambda entry: entry.monotonic_us)
    limited = len(result) > MAX_RECORDS
    return result[-MAX_RECORDS:], limited, unsupported
