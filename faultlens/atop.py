"""Normalize selected Atop system records and report possible temporal overlap only."""
from datetime import datetime, timezone
import hashlib
import re

from .coverage import sample_coverage
from .journal import CLOCK_MAPPING_TOLERANCE_US
from .parsers import counters
from .recordings import recording_date

MAX_SAMPLES = 256
MAX_CORRELATIONS = 500
WINDOW_SECONDS = 1800


def _sample(rows, reset):
    cpu, memory, swap = rows['CPU'], rows['MEM'], rows['SWP']
    if len(cpu) < 11 or len(memory) < 4 or len(swap) < 3:
        raise ValueError('Incomplete resource fields')
    verified = counters(cpu[:11])
    hz, count = verified[:2]
    ticks = verified[2:10]  # guest is already included in user/nice.
    page, total, free, cache = counters(memory[:4])
    swap_page, swap_total, swap_free = counters(swap[:3])
    if (not 1 <= hz <= 1000000 or not 1 <= count <= 65536 or page != swap_page
            or not 512 <= page <= 1048576 or page & (page - 1)
            or total == 0 or free > total or cache > total or swap_free > swap_total):
        raise ValueError('Inconsistent resource measurements')
    total_ticks = sum(ticks)
    def percent(value):
        return None if reset or total_ticks == 0 else round(100 * value / total_ticks, 2)
    return {'since_boot': reset,
            'cpu_busy_percent': percent(total_ticks - ticks[3] - ticks[4]),
            'cpu_execution_percent': percent(total_ticks - ticks[3] - ticks[4] - ticks[7]),
            'cpu_idle_percent': percent(ticks[3]),
            'cpu_iowait_percent': percent(ticks[4]),
            'cpu_steal_percent': percent(ticks[7]),
            'memory_total_bytes': total * page,
            'memory_free_bytes': free * page, 'memory_cache_bytes': cache * page,
            'swap_total_bytes': swap_total * page, 'swap_used_bytes': (swap_total - swap_free) * page}


def samples(text: str) -> list[dict]:
    if len(text.encode('utf-8')) > 262144:
        raise ValueError('Atop output exceeds limit')
    result, rows, reset, header, host = [], {}, False, None, None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line == 'RESET':
            if rows or reset:
                raise ValueError('Unexpected reset boundary')
            reset = True
            continue
        if line == 'SEP':
            if set(rows) != {'CPU', 'MEM', 'SWP'} or len(result) >= MAX_SAMPLES:
                raise ValueError('Incomplete or excessive samples')
            timestamp, interval = header
            if result and timestamp <= result[-1]['timestamp_s']:
                raise ValueError('Ambiguous resource clock order')
            value = _sample(rows, reset)
            value.update(sample_index=len(result), timestamp_s=timestamp, interval_s=interval)
            result.append(value)
            rows, reset, header = {}, False, None
            continue
        fields = line.split()
        if not 9 <= len(fields) <= 64 or fields[0] not in {'CPU', 'MEM', 'SWP'}:
            raise ValueError('Unsupported Atop record')
        label, identity, epoch, date, clock, period = fields[:6]
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', identity):
            raise ValueError('Invalid source identity')
        timestamp, interval = counters([epoch, period])
        if timestamp > 253402300799 or interval > timestamp or (not reset and not 1 <= interval <= 86400):
            raise ValueError('Invalid sample time')
        expected = datetime.fromtimestamp(timestamp, timezone.utc)
        if date.replace('-', '/') != expected.strftime('%Y/%m/%d') or clock != expected.strftime('%H:%M:%S'):
            raise ValueError('Inconsistent UTC header')
        if label in rows or (header is not None and header != (timestamp, interval)) or (host is not None and host != identity):
            raise ValueError('Mixed or duplicate sample metadata')
        if not all(re.fullmatch(r'-?[0-9]{1,20}', field) for field in fields[6:]):
            raise ValueError('Non-numeric resource fields')
        host, header = identity, (timestamp, interval)
        rows[label] = fields[6:]
    if rows or reset:
        raise ValueError('Truncated sample')
    return result


def window_boundary(output: bytearray, end: int):
    """Stop only after a complete, strictly validated sample crosses the window end."""
    position = output.rfind(b'\nSEP\n')
    if position < 0:
        return None
    boundary = position + len(b'\nSEP\n')
    values = samples(output[:boundary].decode('utf-8', errors='strict'))
    return boundary if values and values[-1]['timestamp_s'] >= end else None


def attach(data: dict, records, runner, date: str):
    recording_date(date)
    output = {'state': 'unavailable', 'recording_date': date, 'samples': [], 'correlations': [],
              'host_identity': 'unverified', 'boot_identity': 'unverified',
              'correlation_limit_reached': False, 'coverage': None,
              'limitations': ['Wall-clock overlap is Possible only; it does not verify host/boot identity or a cause.',
                              'Memory free/cache are snapshots, not MemAvailable or evidence of memory pressure.',
                              'One recording and a 30-minute window centered on the last journal record are examined.',
                              'RESET CPU aggregates are excluded; input authenticity and complete coverage are not established.']}
    output['limitations'].extend([
        'CPU percentages are aggregate tick shares over each recorded interval, not instantaneous peaks or per-CPU measurements.',
        'Legacy CPU busy includes steal; CPU execution excludes idle, iowait and steal. Guest ticks are not counted twice.',
        'Iowait accounting is imperfect and can decrease; its share is not disk utilization, latency or proof of storage failure.',
        'Steal is reported involuntary wait, not proof of provider contention or the cause of an incident.'])
    data['atop'] = output
    if not records:
        output['reason'] = 'journal_scope_unavailable'
        return
    offsets = [record.realtime_us - record.monotonic_us for record in records]
    if max(offsets) - min(offsets) > CLOCK_MAPPING_TOLERANCE_US:
        output['reason'] = 'ambiguous_journal_clock_mapping'
        return
    end = records[-1].realtime_us // 1000000 + 900
    start = max(0, end - WINDOW_SECONDS)
    output.update(window_start_s=start, window_end_s=end)
    result = runner.read_atop(date, start, end)
    if result.state not in {'completed', 'window_complete'} or (result.state == 'completed' and result.returncode != 0):
        output['reason'] = 'recording_collection_unavailable'
        return
    try:
        values = [value for value in samples(result.stdout) if start <= value['timestamp_s'] <= end]
    except (ValueError, OverflowError, OSError):
        output['reason'] = 'unsupported_or_ambiguous_samples'
        return
    if not values:
        output['reason'] = 'no_samples_in_window'
        return
    output.update(state='available', collection_state=result.state, samples=values, coverage=sample_coverage(values), output_sha256=hashlib.sha256(result.stdout.encode()).hexdigest())
    for index, finding in enumerate(data['findings']):
        event = finding['evidence'][0]['realtime_us']
        for value in values:
            if (not value['since_boot'] and (value['timestamp_s'] - value['interval_s']) * 1000000
                    < event <= value['timestamp_s'] * 1000000):
                if len(output['correlations']) >= MAX_CORRELATIONS:
                    output['correlation_limit_reached'] = True
                    return
                output['correlations'].append({'finding_index': index, 'sample_index': value['sample_index'],
                    'confidence': 'Possible', 'relationship': 'wall_clock_interval_overlap', 'cause_confidence': 'Unknown',
                    'limitation': 'CPU is an interval average; memory/swap snapshots are at the sample end, not necessarily the event time.'})
