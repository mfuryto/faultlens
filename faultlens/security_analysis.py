"""Bounded, explainable security indicators from already collected evidence."""
from collections import defaultdict, deque
import ipaddress
import statistics

from .incidents import Finding

MAX_FINDINGS = 32
BASELINE_SAMPLES = 5
LIMITATIONS = (
    'Heuristic thresholds are investigation aids, not calibrated attack probabilities or universal capacity limits.',
    'Logging limits, missing records, permissions, rotation and collection caps can hide activity; no findings does not establish security.',
    'Repeated log reports are not necessarily distinct attempts or packets. NAT, proxies, retransmissions and legitimate administration can resemble suspicious patterns.',
    'Reported packet addresses are not authenticated identities; peers are never automatically blocked.',
    'Historical rates use recorded interval counts, not cumulative counter differences. Host/boot identity remains unverified for Atop.',
    'A short local baseline is not a long-term traffic model. Gaps, RESET and missing series break comparisons; clock and interface reuse can still mislead.',
    'Findings remain separate from root-cause assessment and do not establish compromise, DDoS, service failure or external exposure.',
    'Only previously requested local evidence is analyzed; no additional commands, traffic, elevation, reports or configuration changes are triggered.',
)
RECOMMENDATIONS = (
    'Inspect referenced original records and measurements locally; compare expected workload and administrative activity.',
    'Check service capacity, retention, logging policy and existing firewall/authentication policy before considering a change.',
)


def finding(rule, title, observation, evidence, reasoning, thresholds):
    return Finding(rule, title, observation, 'Possible', 'warning', evidence,
                          reasoning, thresholds, LIMITATIONS, RECOMMENDATIONS).to_dict()


def _largest_window(values, width_us, *, distinct_ports=False):
    window, best, best_score = deque(), [], 0
    for value in sorted(values, key=lambda row: row['monotonic_us']):
        window.append(value)
        while value['monotonic_us'] - window[0]['monotonic_us'] > width_us:
            window.popleft()
        score = len({ref['packet']['numeric_fields']['DPT'] for ref in window}) if distinct_ports else len(window)
        if score > best_score:
            best, best_score = list(window), score
    return best


def log_indicators(data):
    groups = defaultdict(list)
    ssh = data.get('ssh_analysis', {})
    firewall = data.get('firewall_analysis', {})
    for value in ssh.get('findings', []) if ssh.get('state') == 'available' else ():
        if value['rule_id'] != 'ssh.password_failed':
            continue
        ref = value['evidence'][0]
        groups[('ssh', ref['boot_id'], str(ipaddress.ip_address(ref['peer_address'])))].append(ref)
    for value in firewall.get('findings', []) if firewall.get('state') == 'available' else ():
        ref = value['evidence'][0]
        packet = ref['packet']
        if packet['protocol'] in {'TCP', 'UDP'}:
            key = (packet['protocol'], ref['boot_id'], str(ipaddress.ip_address(packet['source_address'])),
                   str(ipaddress.ip_address(packet['destination_address'])))
            groups[key].append(ref)
    for key, values in sorted(groups.items()):
        ssh = key[0] == 'ssh'
        width = 300_000_000 if ssh else 60_000_000
        window = _largest_window(values, width)
        if not window:
            continue
        evidence = [{'source_analysis': 'ssh_analysis' if ssh else 'firewall_analysis',
                     'boot_id': key[1], 'reported_source_address': key[2],
                     'candidate_indices': [ref['candidate_index'] for ref in window],
                     'first_monotonic_us': window[0]['monotonic_us'],
                     'last_monotonic_us': window[-1]['monotonic_us'], 'report_count': len(window)}]
        if ssh and len(window) >= 10:
            yield finding('security.ssh_failure_burst', 'Possible SSH password-guessing indicator',
                'At least ten failed-password reports from one reported peer occur within five minutes.', evidence,
                'A bounded monotonic-time window groups supported failure reports by boot and numeric peer; invalid-user reports are not counted again.',
                {'minimum_reports': 10, 'window_seconds': 300})
        if ssh:
            continue
        evidence[0]['reported_destination_address'] = key[3]
        evidence[0]['protocol'] = key[0]
        scan_window = _largest_window(values, width, distinct_ports=True)
        ports = sorted({ref['packet']['numeric_fields']['DPT'] for ref in scan_window})
        scan_evidence = [dict(evidence[0], candidate_indices=[ref['candidate_index'] for ref in scan_window],
            first_monotonic_us=scan_window[0]['monotonic_us'], last_monotonic_us=scan_window[-1]['monotonic_us'],
            report_count=len(scan_window), destination_ports=ports)]
        if len(ports) >= 10:
            yield finding('security.port_scan_indicator', 'Possible multi-port probing indicator',
                'One reported source addresses at least ten destination ports on one destination within a minute.', scan_evidence,
                'Supported TCP/UDP packet reports are grouped separately by protocol, boot, source and destination; distinct reported destination ports meet the heuristic.',
                {'minimum_distinct_destination_ports': 10, 'window_seconds': 60})
        if key[0] == 'UDP' and len(window) >= 100:
            yield finding('security.udp_report_burst', 'Possible UDP traffic burst indicator',
                'At least one hundred UDP-labelled packet reports share a source and destination within a minute.', evidence,
                'The report-count threshold is met; logging duplication/rate limits prevent inference of packet rate or a UDP flood.',
                {'minimum_reports': 100, 'window_seconds': 60})


def _series(sample):
    extended = sample.get('extended', {})
    if sample.get('since_boot') or extended.get('state') != 'available':
        return {}
    values = {}
    for row in extended.get('interfaces', []):
        for field, minimum in (('received_bytes', 100000), ('received_packets', 100),
                               ('receive_errors', 1), ('receive_drops', 1)):
            values[('interface', row['interface'], field)] = (row[field], minimum)
    protocols = extended.get('network_protocols') or {}
    for field, minimum in (('tcp_in_segments', 100), ('udp_in_datagrams', 100),
                           ('tcp_active_opens', 10), ('tcp_passive_opens', 10),
                           ('udp_input_errors', 1), ('tcp_retransmitted_segments', 10)):
        if field in protocols:
            values[('protocol', 'namespace', field)] = (protocols[field], minimum)
    return values


def traffic_indicators(atop, progress):
    history = {}
    previous = None
    for sample in atop.get('samples', []):
        interval, timestamp = sample['interval_s'], sample['timestamp_s']
        current = _series(sample)
        if previous is None or timestamp - previous != interval or not current or interval <= 0:
            history = {}
        previous = timestamp
        history = {key: values for key, values in history.items() if key in current}
        if interval <= 0:
            continue
        for key, (count, minimum) in current.items():
            rate = count / interval
            baseline = history.setdefault(key, deque(maxlen=BASELINE_SAMPLES))
            if len(baseline) == BASELINE_SAMPLES:
                progress['compared_series_windows'] += 1
                median = statistics.median(row['rate'] for row in baseline)
                if rate >= minimum and rate > 5 * median:
                    yield finding('security.historical_traffic_anomaly', 'Recorded network rate exceeds its short local baseline',
                        key[2] + ' exceeds five times the median of five preceding contiguous recorded intervals.',
                        [{'source': 'atop', 'output_sha256': atop.get('output_sha256'),
                          'sample_index': sample['sample_index'], 'baseline_sample_indices': [row['index'] for row in baseline],
                          'series': list(key), 'recorded_count': count, 'interval_seconds': interval,
                          'observed_per_second': rate, 'baseline_median_per_second': median}],
                        'Recorded interval counts are normalized by their own duration. RESET, gaps and missing series restart the five-sample baseline. UDP/TCP/open-rate and interface changes are indicators only.',
                        {'baseline_samples': BASELINE_SAMPLES, 'strict_median_multiplier': 5, 'minimum_per_second': minimum})
            baseline.append({'rate': rate, 'index': sample['sample_index']})


def assess(data):
    """Analyze trusted internal source models; never parse or collect a new source."""
    sources = {key: data.get(key, {}).get('state', 'not_requested')
               for key in ('ssh_analysis', 'firewall_analysis', 'atop')}
    progress = {'compared_series_windows': 0}
    findings, total = [], 0
    for value in log_indicators(data):
        total += 1
        if len(findings) < MAX_FINDINGS:
            findings.append(value)
    atop = data.get('atop', {})
    for value in traffic_indicators(atop if atop.get('state') == 'available' else {}, progress):
        total += 1
        if len(findings) < MAX_FINDINGS:
            findings.append(value)
    available = sum(state == 'available' for state in sources.values())
    requested = sum(state != 'not_requested' for state in sources.values())
    data['security_analysis'] = {'state': 'not_requested' if not requested else
        'unavailable' if not available else 'available' if available == requested else 'partial',
        'sources': sources, 'findings': findings, 'finding_limit': MAX_FINDINGS,
        'findings_truncated': total > MAX_FINDINGS, 'matching_indicators': total,
        'historical_comparison': dict(progress, state='compared' if progress['compared_series_windows'] else 'insufficient_comparable_history'), 'attack_assessment': 'Unknown', 'root_cause': 'Unknown',
        'limitations': list(LIMITATIONS), 'recommendations': list(RECOMMENDATIONS)}
