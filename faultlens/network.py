"""Local namespace counter sampling; no endpoints, packets or attack attribution."""
from dataclasses import asdict
import math
import re
import time

from .incidents import Finding
from .linux import LinuxSources
from .models import Observation, report, unavailable
from .parsers import counters, network as interfaces

TCP_FIELDS = ('SyncookiesSent', 'SyncookiesRecv', 'SyncookiesFailed', 'ListenOverflows', 'ListenDrops')
LIMITATIONS = (
    'Current network namespace only; no host-wide visibility or stable interface identity is established.',
    'Two sequential snapshots are not atomic. Rates use the measured batch interval and can hide short peaks.',
    'Counter resets/decreases and changed interface sets prevent comparisons; reuse of a name without a decrease can be undetectable.',
    'Virtual/physical interfaces can count the same traffic; interface values must not be summed as host throughput.',
    'Counter sampling collects no endpoints or payloads; --sockets separately opts in to local endpoint collection. No DNS, packet capture or remote probes are used.',
    'No traffic baseline, SSH logs, firewall policy or historical security evidence is analyzed in this milestone.',
    'No supported indicator or a zero delta does not establish security. Attack and root-cause assessments remain Unknown.',
    'Root/kernel compromise can falsify counters. No sysctl, interface or firewall settings are changed.',
)


def tcp_extensions(text):
    if len(text.encode()) > 262144:
        raise ValueError('Network statistics exceed limit')
    lines = text.splitlines()
    if len(lines) > 32 or len(lines) % 2:
        raise ValueError('Invalid network statistics pairs')
    result, sections = None, set()
    for header, values in zip(lines[::2], lines[1::2]):
        names, numbers = header.split(), values.split()
        if (not names or not numbers or names[0] != numbers[0]
                or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,63}:', names[0])
                or names[0] in sections or not 2 <= len(names) <= 513
                or len(names) != len(numbers) or len(set(names[1:])) != len(names)-1
                or not all(re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,63}', name) for name in names[1:])):
            raise ValueError('Ambiguous network statistics')
        sections.add(names[0])
        parsed = dict(zip(names[1:], counters(numbers[1:])))
        if names[0] == 'TcpExt:':
            result = {name: parsed.get(name) for name in TCP_FIELDS}
    if result is None:
        raise ValueError('TCP extension section missing')
    return result


def _snapshot(sources):
    result = {}
    for key, path, parser in (('interfaces', '/proc/net/dev', interfaces),
                              ('tcp', '/proc/net/netstat', tcp_extensions)):
        try:
            text = sources.read(path)
            if len(text.encode()) > 262144:
                raise ValueError('Network source exceeds limit')
            result[key] = parser(text)
        except (OSError, ValueError, UnicodeError):
            result[key] = None
    return result


def collect(sources=None, *, command='network', sample_seconds=0.1, sleep=time.sleep, clock=time.monotonic):
    if command not in {'network', 'security'} or not isinstance(sample_seconds, (float, int)) or isinstance(sample_seconds, bool) or not math.isfinite(sample_seconds) or not 0.05 <= sample_seconds <= 1:
        raise ValueError('Invalid network sample')
    sources = sources or LinuxSources()
    started = clock()
    before = _snapshot(sources)
    sleep(sample_seconds)
    after = _snapshot(sources)
    elapsed = clock() - started
    valid_time = math.isfinite(elapsed) and 0.001 <= elapsed <= 5
    items, findings = [], []
    for key, source in (('interfaces', '/proc/net/dev'), ('tcp', '/proc/net/netstat')):
        if before[key] is None or after[key] is None or not valid_time:
            items.append(unavailable('network.' + key, source, 'Both valid snapshots and a bounded positive monotonic interval are required.'))
            continue
        if key == 'interfaces':
            old = {row['interface']: row for row in before[key]}
            new = {row['interface']: row for row in after[key]}
            values = []
            for name in sorted(old.keys() | new.keys()):
                row = {'interface': name, 'state': 'not_comparable', 'before': old.get(name), 'after': new.get(name), 'delta': None, 'per_second': None}
                if name in old and name in new:
                    delta = {field: value - old[name][field] for field, value in new[name].items() if field != 'interface'}
                    if all(value >= 0 for value in delta.values()):
                        row.update(state='compared', delta=delta, per_second={field: round(value/elapsed, 2) for field, value in delta.items()})
                values.append(row)
            items.append(Observation('network.interfaces', values, 'bytes/packets/events and per second', source,
                'unknown', explanation='Two visible counter snapshots; changed/reset interfaces have no inferred rates.', limitations=LIMITATIONS))
        else:
            for name in TCP_FIELDS:
                first, last = before[key][name], after[key][name]
                if first is None or last is None or last < first:
                    items.append(unavailable('network.tcp.' + name, source, 'Counter missing, reset or decreased; no delta is inferred.'))
                    continue
                delta = last-first
                items.append(Observation('network.tcp.' + name, {'before': first, 'after': last, 'delta': delta},
                    'events', source, 'unknown', explanation='Observed namespace TCP extension counter change only.', limitations=LIMITATIONS))
                if delta > 0 and name in {'SyncookiesSent', 'ListenOverflows', 'ListenDrops'}:
                    title = {'SyncookiesSent': 'SYN cookie counter increased', 'ListenOverflows': 'TCP listen overflow counter increased',
                             'ListenDrops': 'TCP listen drop counter increased'}[name]
                    findings.append(Finding('network.tcp.' + name, title, title + ' during the sampled interval.',
                        'Confirmed', 'warning', [{'source': source, 'counter': name, 'before': first, 'after': last,
                                                'delta': delta, 'sample_elapsed_seconds': elapsed}],
                        'A supported kernel counter increased between two valid monotonic-time snapshots.',
                        {'minimum_counter_delta': 1},
                        ('Confirms counter growth, not a SYN flood, DDoS, malicious source, service outage or root cause.',
                         'Legitimate bursts, slow listeners, resource limits and SYN-cookie policy can produce these observations.',
                         'Counters can overlap; multiple findings are not independent attacks or connection counts.'),
                        ('Review legitimate load, listener capacity and existing local policy before considering any change.',)))
    data = report(command, items)
    available = sum(item.state != 'unavailable' for item in items)
    incomplete = any(item.state == 'unavailable' for item in items)
    if after['interfaces'] is not None and before['interfaces'] is not None:
        incomplete |= any(row['state'] != 'compared' for item in items if item.key == 'network.interfaces' and item.value is not None for row in item.value)
    data.update(state='unavailable' if not available else 'partial' if incomplete else 'available',
                sample={'requested_seconds': sample_seconds, 'elapsed_seconds': elapsed if valid_time else None},
                namespace='current', completeness='unknown', attack_assessment='Unknown', root_cause='Unknown',
                findings=[asdict(finding) for finding in findings])
    data['limitations'].extend(LIMITATIONS)
    return data
