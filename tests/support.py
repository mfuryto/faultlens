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
                'unsafe_entries': 0, 'unsupported_entries': 0, 'oldest_date': '20260101', 'newest_date': '20260102',
                'filename_coverage': {'date_ranges': [], 'missing_filename_days': 0,
                                      'assessment': 'Synthetic contiguous filename dates only.'}}

    def pstore_snapshot(self):
        from faultlens.pstore import Record
        payload = (b"Kernel panic - not syncing: synthetic test\n" + b"synthetic kernel context\n" * 3000)[:65536]
        return ([Record(payload, 'dmesg-ramoops-'+str(index), {'uid':0, 'gid':0, 'mode_octal':'0600',
                  'observed_size_bytes':len(payload), 'mtime_ns':1767225600000000000,
                  'ctime_ns':1767225600000000000, 'inode':index+1, 'device':1}) for index in range(8)], 0)

    def process_count(self):
        return 20


class SyntheticRunner:
    def __init__(self):
        self.calls = []
        from tests.network_context_fixtures import reply
        self.results = {
            **{command:reply(command) for command in (Command.NETWORK_ADDRESSES,Command.NETWORK_ROUTES4,Command.NETWORK_ROUTES6,Command.SOCKET_OWNERS)},
            Command.LOGIN_SESSION_SERVICE: Result('missing'),
            Command.LOGIN_SESSION_LIST: Result('missing'),
            Command.LOGIN_SESSIONS: Result('completed','example-admin pts/0 2026-01-01 12:34 . 42 (192.0.2.8)\n',0),
            Command.FAILED_SERVICES: Result('completed','',0),
            Command.JOURNAL_CONFIG: Result('completed', '# /etc/systemd/journald.conf\n[Journal]\nStorage=persistent\nSystemMaxUse=64M\nMaxRetentionSec=7day\n', 0),
            Command.SYSTEM_STATE: Result('completed', 'running\n', 0),
            Command.JOURNAL_BOOTS: Result('completed', '-1 ' + 'a' * 32 + ' synthetic previous boot\n0 ' + 'b' * 32 + ' synthetic current boot\n', 0),
            Command.JOURNAL_SERVICE: Result('completed', 'active\n', 0),
            Command.ATOP_SERVICE: Result('missing'),
        }

    def read_system_resources(self,kind,sample_seconds):
        import json
        from tests.system_resource_fixtures import process_report,storage_report
        self.calls.append(('resource',kind))
        return Result('completed',json.dumps(process_report(getattr(self,'maximum_system_resources',False)) if kind=='processes' else storage_report(getattr(self,'maximum_system_resources',False))),0)

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

    def read_boot_window(self, boot_id, since_us, *, until_us=None, system=False):
        import json
        result = self.read_boot(boot_id)
        if result.state != 'completed':
            return result
        rows = [line for line in result.stdout.splitlines()
                if int(json.loads(line)['__REALTIME_TIMESTAMP']) >= since_us
                and (until_us is None or int(json.loads(line)['__REALTIME_TIMESTAMP']) <= until_us)]
        return Result('completed', '\n'.join(rows), 0)

    def read_boot_until(self, boot_id, until_us, *, system=False):
        import json
        result = self.read_boot(boot_id)
        if result.state != 'completed':
            return result
        rows = [line for line in result.stdout.splitlines()
                if int(json.loads(line)['__REALTIME_TIMESTAMP']) <= until_us]
        return Result('completed', '\n'.join(rows), 0)

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


class SyntheticStallRunner(SyntheticHistoricalRunner):
    """Bounded mixed detector reports with invented task names and timings."""
    def read_boot(self, boot_id):
        import json
        result = super().read_boot(boot_id)
        if result.state != 'completed':
            return result
        messages = ('watchdog: BUG: soft lockup - CPU#2 stuck for 26s! [synthetic-task:42]',
                    'watchdog: Watchdog detected hard LOCKUP on cpu 3',
                    'INFO: task synthetic-task:42 blocked for more than 120 seconds.')
        rows = []
        for index, line in enumerate(result.stdout.splitlines()):
            value = json.loads(line)
            value['MESSAGE'] = messages[index % len(messages)]
            rows.append(json.dumps(value))
        return Result('completed', '\n'.join(rows), 0)


class SyntheticClockRunner(SyntheticStallRunner):
    """Worst-case bounded mapping changes without changing any real system clock."""
    def read_boot(self, boot_id):
        import json
        result = super().read_boot(boot_id)
        if result.state != 'completed':
            return result
        rows = []
        for index, line in enumerate(result.stdout.splitlines()):
            value = json.loads(line)
            value['__REALTIME_TIMESTAMP'] = str(int(value['__REALTIME_TIMESTAMP']) + (index % 2) * 3000000)
            rows.append(json.dumps(value))
        return Result('completed', '\n'.join(rows), 0)


class SyntheticSystemRunner(SyntheticHistoricalRunner):
    """Explicit system-scope interface using invented boot and record data only."""
    def run(self, command):
        if command == Command.JOURNAL_SYSTEM_BOOTS:
            self.calls.append(command)
            return self.results[Command.JOURNAL_BOOTS]
        return super().run(command)

    def read_system_boot(self, boot_id):
        return self.read_boot(boot_id)


class SyntheticEventRunner(SyntheticSystemRunner):
    """Maximum filtered candidates from invented data, independently of the tail."""
    def read_event_candidates(self, boot_id, query, *, system=False, since_us=None, until_us=None):
        import json
        if query not in {'kernel_warnings', 'systemd_events'}:
            raise ValueError('Unknown synthetic query')
        result = self.read_boot(boot_id)
        if result.state != 'completed':
            return result
        rows = []
        for line in result.stdout.splitlines():
            value = json.loads(line)
            if query == 'kernel_warnings':
                value['PRIORITY'] = '3'
            else:
                from faultlens.journal import UNIT_START_FAILED
                value.update(_TRANSPORT='journal', _PID='1', _COMM='systemd',
                             MESSAGE_ID=UNIT_START_FAILED, MESSAGE='Synthetic start-job event', PRIORITY='6')
            if (since_us is None or int(value['__REALTIME_TIMESTAMP'])>=since_us) and (until_us is None or int(value['__REALTIME_TIMESTAMP'])<=until_us):
                rows.append(json.dumps(value))
        return Result('completed', '\n'.join(rows), 0)


class SyntheticReviewRunner(SyntheticEventRunner):
    """Maximum unclassified kernel candidates without using private host messages."""
    def read_event_candidates(self, boot_id, query, *, system=False, since_us=None, until_us=None):
        import json
        result = super().read_event_candidates(boot_id, query, system=system,since_us=since_us,until_us=until_us)
        if query != 'kernel_warnings' or result.state != 'completed':
            return result
        rows = []
        for line in result.stdout.splitlines():
            value = json.loads(line)
            value['MESSAGE'] = 'Unclassified synthetic kernel warning'
            rows.append(json.dumps(value))
        return Result('completed', '\n'.join(rows), 0)


class SyntheticOverlayRunner(SyntheticHistoricalRunner):
    """Bounded invented OverlayFS report variants without mounting filesystems."""
    def read_boot(self, boot_id):
        import json
        result = super().read_boot(boot_id)
        if result.state != 'completed':
            return result
        rows = []
        for index, line in enumerate(result.stdout.splitlines()):
            value = json.loads(line)
            role = 'upperdir' if index % 2 else 'workdir'
            value['MESSAGE'] = ('overlayfs: ' + role + ' is in-use as upperdir/workdir of another mount, '
                                'accessing files from both mounts will result in undefined behavior.')
            rows.append(json.dumps(value))
        return Result('completed', '\n'.join(rows), 0)


class SyntheticJournalLossRunner(SyntheticHistoricalRunner):
    """Maximum invented driver loss reports without provoking real log loss."""
    def read_boot(self, boot_id):
        import json
        from faultlens.journal import JOURNAL_DROPPED, JOURNAL_MISSED
        result = super().read_boot(boot_id)
        if result.state != 'completed':
            return result
        rows = []
        for index, line in enumerate(result.stdout.splitlines()):
            value = json.loads(line)
            value.update(_TRANSPORT='driver', MESSAGE_ID=JOURNAL_DROPPED if index % 2 else JOURNAL_MISSED,
                         MESSAGE='Synthetic journal-driver report')
            rows.append(json.dumps(value))
        return Result('completed', '\n'.join(rows), 0)


class SyntheticOverviewRunner(SyntheticHistoricalRunner):
    """Seven invented previous boots with maximum journal tails."""
    def __init__(self):
        super().__init__()
        identities = [format(index + 1, '032x') for index in range(8)]
        self.results[Command.JOURNAL_BOOTS] = Result('completed', '\n'.join(
            f'{-index} {identity} synthetic' for index, identity in enumerate(identities)), 0)

    def read_boot(self, boot_id):
        result = super().read_boot('a' * 32)
        return Result(result.state, result.stdout.replace('a' * 32, boot_id), result.returncode)


class SyntheticExtendedRunner(SyntheticEventRunner):
    """Bounded invented resource groups; names are generated, never host-derived."""
    def read_atop_extended(self, date, start, end):
        from tests.test_atop_extended import extended_sample
        text = extended_sample()
        # The existing incident tail falls within this invented sample interval.
        return Result('completed', text, 0)


class SyntheticMaximumExtendedRunner(SyntheticExtendedRunner):
    """Maximum supported device/interface/process cardinality in one sample."""
    def read_atop_extended(self, date, start, end):
        from tests.test_atop_extended import extended_sample
        rows = [('NET', 'upper ' + '0 ' * 16 + '0')]
        rows += [('DSK', f'disk{index} 0 1 2 3 4 -1 -1 0 0.00') for index in range(32)]
        rows += [('NET', f'nic{index} 1 2 3 4 -1 0 0 0 0 0 0 0 0 0 0 0 0 0') for index in range(32)]
        for index in range(256):
            pid = index + 1
            rows += [('PRC', f'{pid} synthetic S 100 2 1 0 20 0 0 0 0 {pid} y 0 _ 0 -3 -2 0 0'),
                     ('PRM', f'{pid} synthetic S 4096 20 10 0 0 0 0 0 0 0 0 0 {pid} y 0 0 -3 -2 -3 -2')]
        return Result('completed', extended_sample(rows=rows), 0)


class SyntheticNetworkSources(SyntheticSources):
    """Maximum interface set and invented supported TCP indicator growth."""
    def __init__(self):
        super().__init__()
        self.network_reads = {}

    def read(self, path, limit=262144):
        if path not in {'/proc/net/dev', '/proc/net/netstat', '/proc/net/snmp','/proc/net/snmp6'}:
            return super().read(path, limit)
        index = self.network_reads.get(path, 0)
        self.network_reads[path] = index+1
        if path == '/proc/net/snmp6':
            return '\n'.join(key+' 0' for key in ('Udp6InDatagrams','Udp6OutDatagrams','Udp6NoPorts','Udp6InErrors','Udp6RcvbufErrors','Udp6SndbufErrors'))+'\n'
        if path == '/proc/net/snmp':
            return 'Tcp: ActiveOpens PassiveOpens AttemptFails EstabResets InSegs OutSegs RetransSegs InErrs OutRsts\nTcp: 1 2 0 0 10 20 0 0 0\nUdp: InDatagrams OutDatagrams NoPorts InErrors RcvbufErrors SndbufErrors\nUdp: 1 2 0 0 0 0\n'
        if path == '/proc/net/netstat':
            return ('TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed ListenOverflows ListenDrops\n'
                    + 'TcpExt: ' + ' '.join(str(index) for _ in range(5)) + '\n')
        header = self.values['/proc/net/dev'].splitlines()[:2]
        rows = [f'net{number}: {100+index} 10 0 0 0 0 0 0 {200+index} 20 0 0 0 0 0 0' for number in range(128)]
        return '\n'.join(header+rows)+'\n'


class SyntheticSshRunner(SyntheticEventRunner):
    """Maximum invented SSH candidate tail with inspectable local evidence."""
    def read_ssh_candidates(self, boot_id, *, system=False, since_us=None, until_us=None):
        import json
        rows = []
        for index in range(501):
            rows.append(json.dumps({'_BOOT_ID': boot_id, '__REALTIME_TIMESTAMP': str(1767225600000000+index),
                '__MONOTONIC_TIMESTAMP': str(index), '__CURSOR':'i='+str(index),
                '_UID':'0', '_PID':'42', '_COMM':'sshd', '_TRANSPORT':'syslog', 'PRIORITY':'6',
                'MESSAGE':'Failed password for invalid user synthetic-admin from 192.0.2.7 port 2222 ssh2'}))
        return Result('completed', '\n'.join(rows), 0)


class SyntheticFirewallRunner(SyntheticSshRunner):
    """Maximum invented kernel candidates with a UFW-style packet report."""
    def read_firewall_candidates(self, boot_id, *, system=False, since_us=None, until_us=None):
        import json
        text = ('[UFW BLOCK] IN=synthetic0 OUT= SRC=192.0.2.7 DST=198.51.100.8 '
                'LEN=60 PROTO=TCP SPT=1234 DPT=22 SYN')
        rows = [json.dumps({'_BOOT_ID':boot_id, '__REALTIME_TIMESTAMP':str(1767225600000000+index),
            '__MONOTONIC_TIMESTAMP':str(index), '__CURSOR':'i='+str(index), '_TRANSPORT':'kernel',
            'PRIORITY':'4', 'MESSAGE':text}) for index in range(501)]
        return Result('completed','\n'.join(rows),0)


class SyntheticSocketRunner(SyntheticRunner):
    def run(self, command):
        if command != Command.SOCKETS:
            from tests.network_context_fixtures import reply
            return reply(command,maximum=True)
        return Result('completed', ''.join(
            f'tcp ESTAB 0 0 192.0.2.1:{10000+i} 198.51.100.1:443\n' for i in range(512)), 0)


class SyntheticPhase3Runner(SyntheticFirewallRunner):
    """Invented complete phase 3 evidence with short contiguous traffic history."""
    def read_atop_extended(self, date, start, end):
        from tests.test_atop import EPOCH
        from tests.test_atop_extended import extended_sample
        result = []
        for index in range(6):
            count = 100000 if index == 5 else 10
            rows = [('NET', 'upper ' + ' '.join(str(count) for _ in range(17)))]
            rows += [('NET', f'nic{i} {count} {count*1000} 1 2 -1 0 0 0 0 0 0 0 0 0 0 0 0 0') for i in range(32)]
            result.append(extended_sample(rows=rows, timestamp=EPOCH+30*(index+1)))
        return Result('completed', ''.join(result), 0)


class SyntheticHealthRunner(SyntheticRunner):
    """Bounded many-failure scenario; invented units/descriptions, never host state."""
    def __init__(self):
        super().__init__()
        self.results[Command.SYSTEM_STATE]=Result('completed','degraded\n',1)
        self.results[Command.FAILED_SERVICES]=Result('completed',''.join(
            'example-'+str(i)+'.service loaded failed failed Synthetic '+('context '*128)+'\n'
            for i in range(128)),0)
