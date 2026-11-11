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

    def process_count(self):
        return 20


class SyntheticRunner:
    def __init__(self):
        self.calls = []
        self.results = {
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
