"""Invented Linux source data; never recorded from a real machine."""
from types import SimpleNamespace

from faultlens.commands import Command, Result


class SyntheticSources:
    def __init__(self):
        self.reads = 0
        self.values = {
            '/proc/stat': 'cpu 100 0 100 800 0 0 0 0 20 0\ncpu0 100 0 100 800 0 0 0 0\nbtime 1767225600\n',
            '/proc/loadavg': '0.10 0.20 0.30 1/20 100\n',
            '/proc/meminfo': 'MemTotal: 1000 kB\nMemAvailable: 500 kB\nSwapTotal: 100 kB\nSwapFree: 75 kB\n',
            '/proc/uptime': '1000.50 800.00\n',
            '/proc/diskstats': '8 0 vda 1 0 2 0 1 0 4 0 0 5 0\n',
            '/proc/net/dev': 'Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n eth0: 1024 10 0 0 0 0 0 0 2048 20 0 0 0 0 0 0\n',
            '/etc/default/atop': 'LOGINTERVAL=600\nLOGGENERATIONS=28\nLOGPATH=/var/log/atop\n',
            '/proc/sys/kernel/osrelease': '6.1.0-synthetic\n',
        }

    def read(self, path, limit=262144):
        if path == '/proc/stat':
            self.reads += 1
            if self.reads % 2 == 0:
                return 'cpu 110 0 110 880 0 0 0 0 20 0\ncpu0 110 0 110 880 0 0 0 0\nbtime 1767225600\n'
        return self.values[path]

    def filesystem(self):
        return SimpleNamespace(f_blocks=1000, f_bfree=400, f_bavail=350, f_frsize=4096)

    def directory(self, path):
        return path in {'/var/log/journal', '/sys/fs/pstore'}

    def log_filesystem(self, kind):
        return self.filesystem()

    def recording_inventory(self):
        return {'files': 2, 'logical_bytes': 10000, 'empty_files': 0, 'oversized_files': 0,
                'unsafe_entries': 0, 'unsupported_entries': 0, 'oldest_date': '20260101', 'newest_date': '20260102'}

    def process_count(self):
        return 20


class SyntheticRunner:
    def __init__(self):
        self.calls = []
        self.results = {
            Command.JOURNAL_CONFIG: Result('completed', '# /etc/systemd/journald.conf\n[Journal]\nStorage=persistent\nSystemMaxUse=64M\nMaxRetentionSec=7day\n', 0),
            Command.SYSTEM_STATE: Result('completed', 'running\n', 0),
            Command.JOURNAL_BOOTS: Result('completed', '-1 ' + 'a' * 32 + ' synthetic previous boot\n0 ' + 'b' * 32 + ' synthetic current boot\n', 0),
            Command.JOURNAL_SERVICE: Result('completed', 'active\n', 0),
            Command.ATOP_SERVICE: Result('missing'),
        }

    def available(self, name):
        return name in {'systemctl', 'journalctl'}

    def run(self, command):
        self.calls.append(command)
        return self.results[command]


class SyntheticHistoricalRunner(SyntheticRunner):
    """Worst-case bounded tail, generated from invented events only."""
    def read_boot(self, boot_id):
        import json
        if boot_id != 'a' * 32:
            return Result('unavailable')
        return Result('completed', '\n'.join(json.dumps({
            '_BOOT_ID': boot_id, '__REALTIME_TIMESTAMP': str(1767225600000000 + index),
            '__MONOTONIC_TIMESTAMP': str(index), '__CURSOR': 'i=' + str(index),
            '_TRANSPORT': 'kernel', 'MESSAGE': 'Out of memory: Killed process 42 (synthetic)'
        }) for index in range(501)), 0)

    def read_atop(self, date, start, end):
        from datetime import datetime, timezone
        rows = []
        for index in range(256):
            timestamp = 1767225601 + index * 2
            moment = datetime.fromtimestamp(timestamp, timezone.utc)
            header = f'synthetic.test {timestamp} {moment:%Y/%m/%d} {moment:%H:%M:%S} 1'
            rows += ['CPU ' + header + ' 100 1 10 10 0 80 0 0 0 0 50',
                     'MEM ' + header + ' 4096 1000 400 300',
                     'SWP ' + header + ' 4096 100 25', 'SEP']
        return Result('completed', '\n'.join(rows), 0)
