"""Bounded current-namespace TCP/UDP observations without remote traffic."""
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import re

from .commands import Command, CommandRunner

MAX_ROWS = 512
STATES = {'UNKNOWN', 'ESTAB', 'SYN-SENT', 'SYN-RECV', 'FIN-WAIT-1', 'FIN-WAIT-2',
          'TIME-WAIT', 'UNCONN', 'CLOSE-WAIT', 'LAST-ACK', 'LISTEN', 'CLOSING', 'NEW-SYN-RECV'}
LIMITATIONS = (
    'Current network namespace and existing permissions only; collection is non-atomic and transient.',
    'A wildcard or non-loopback binding does not establish external reachability, firewall policy or a vulnerability.',
    'TCP/UDP only; bound-inactive TCP, UNIX sockets and other namespaces are not collected. The base query does not read owners; requested context supplies separate reported associations.',
    'Queue values are native ss values; listening queues and connected queues have different semantics.',
    'No reverse DNS, service lookup, remote connection, packet capture, elevation or configuration change is performed.',
    'Original accepted rows and numeric endpoints are retained without privacy masking; terminal escaping is reversible.',
    'At most 512 rows and 256 KiB within two seconds; exceeding a bound or unsupported output makes this source unavailable.',
    'No sockets found does not establish security or absence of services. Kernel/root compromise can falsify evidence.',
)


def endpoint(value):
    host, separator, port = value.rpartition(':')
    if not separator or not host or not (port == '*' or re.fullmatch(r'[0-9]{1,5}', port) and int(port) <= 65535):
        raise ValueError('Unsupported endpoint')
    # ss can print [IPv6]%device as well as [IPv6%device].
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    if host != '*':
        address, scope, zone = host.partition('%')
        if address.startswith('[') and address.endswith(']'):
            address = address[1:-1]
        ipaddress.ip_address(address)
        if scope and not re.fullmatch(r'[A-Za-z0-9_.:@!-]{1,64}', zone):
            raise ValueError('Unsupported scope')
        host = address + ('%' + zone if scope else '')
    return {'address': host, 'port': None if port == '*' else int(port), 'original': value}


def parse(text):
    if len(text.encode('utf-8')) > 262144:
        raise ValueError('Socket output exceeds limit')
    if any(c not in '\t\n' and not 32 <= ord(c) <= 126 for c in text):
        raise ValueError('Unsupported socket output characters')
    lines = text.splitlines()
    if len(lines) > MAX_ROWS:
        raise ValueError('Socket row limit exceeded')
    rows = []
    for index, line in enumerate(lines):
        fields = line.split()
        if (len(line) > 8192 or len(fields) != 6 or fields[0] not in {'tcp', 'udp'}
                or fields[1] not in STATES or any(ord(c) < 32 and c != '\t' for c in line)
                or not all(re.fullmatch(r'[0-9]{1,20}', v) and int(v) <= 2**64-1 for v in fields[2:4])):
            raise ValueError('Unsupported socket row')
        rows.append({'row_index': index, 'protocol': fields[0], 'state': fields[1],
                     'receive_queue': int(fields[2]), 'send_queue': int(fields[3]),
                     'local': endpoint(fields[4]), 'peer': endpoint(fields[5]), 'original': line})
    return rows


def attach(data, runner=None):
    started_at = datetime.now(timezone.utc).isoformat()
    result = (runner or CommandRunner()).run(Command.SOCKETS)
    snapshot = {'state': 'unavailable', 'command_state': result.state, 'returncode': result.returncode,
                'started_at': started_at, 'finished_at': datetime.now(timezone.utc).isoformat(),
                'source': 'ss', 'namespace': 'current', 'completeness': 'unknown', 'rows': [],
                'limitations': list(LIMITATIONS), 'reason': 'command_unsuccessful'}
    if result.state == 'completed' and result.returncode == 0:
        try:
            snapshot['rows'] = parse(result.stdout)
            snapshot.update(state='available', reason=None,
                reported_state_counts=dict(sorted(Counter(row['protocol'] + '.' + row['state'] for row in snapshot['rows']).items())),
                tcp_listener_rows=sum(row['protocol'] == 'tcp' and row['state'] == 'LISTEN' for row in snapshot['rows']))
        except (ValueError, UnicodeError):
            snapshot['reason'] = 'unsupported_or_over_limit_output'
    data['sockets'] = snapshot
    data['limitations'].extend(LIMITATIONS)
    if snapshot['state'] != 'available' or data['state'] == 'unavailable':
        data['state'] = 'partial' if snapshot['state'] == 'available' or data['state'] != 'unavailable' else 'unavailable'
