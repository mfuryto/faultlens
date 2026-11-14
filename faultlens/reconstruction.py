"""Describe retained journal chronology without causal or whole-boot inference."""
from collections import Counter

from .journal import CLOCK_MAPPING_TOLERANCE_US, MAX_RECORDS

MAX_CLOCK_EXAMPLES = 16
LIMITATIONS = [
    'Only retained selected-boot records are described; first/last visible records are not boot or incident boundaries.',
    'Intervals without records do not prove lost logging, inactivity, downtime or a freeze.',
    'Journal receipt timestamps are not necessarily event times. Temporal order does not establish causality.',
    'Equal monotonic timestamps retain input order; their actual relative order is unresolved.',
    'Clock mapping variation can reflect corrections, suspend or source semantics; its cause is not inferred.',
    'Finding counts describe reports, not independent incidents. Root cause and complete shutdown remain unverified.',
]


def describe(records, findings, limited, unsupported):
    if len(records) > MAX_RECORDS or len(findings) > 2 * MAX_RECORDS:
        raise ValueError('Reconstruction exceeds retained evidence limits')
    if not records:
        return {'state': 'unavailable', 'reason': 'no_retained_records', 'limitations': list(LIMITATIONS)}
    first, last = records[0], records[-1]
    offsets = [entry.realtime_us - entry.monotonic_us for entry in records]
    changes, change_count, reversals, ties, tied_wall_differences, largest = [], 0, 0, 0, 0, None
    for index, (previous, current) in enumerate(zip(records, records[1:]), 1):
        delta = current.monotonic_us - previous.monotonic_us
        if delta < 0 or current.boot_id != first.boot_id:
            raise ValueError('Ambiguous reconstruction scope or order')
        if largest is None or delta > largest['duration_us']:
            largest = {'duration_us': delta, 'before': previous.reference(), 'after': current.reference()}
        ties += delta == 0
        reversals += delta > 0 and current.realtime_us < previous.realtime_us
        tied_wall_differences += delta == 0 and current.realtime_us != previous.realtime_us
        offset_delta = offsets[index] - offsets[index - 1]
        if abs(offset_delta) > CLOCK_MAPPING_TOLERANCE_US:
            change_count += 1
            if len(changes) < MAX_CLOCK_EXAMPLES:
                changes.append({'before': previous.reference(), 'after': current.reference(),
                                'offset_change_us': offset_delta,
                                'relative_order': 'unresolved_equal_timestamp' if delta == 0 else 'monotonic_report_order'})
    offset_range = max(offsets) - min(offsets)
    return {'state': 'available', 'scope': 'retained_selected_boot_tail',
            'record_count': len(records), 'record_limit_reached': limited,
            'unsupported_messages_in_collected_response': unsupported,
            'first_record': first.reference(), 'last_record': last.reference(),
            'monotonic_span_us': last.monotonic_us - first.monotonic_us,
            'largest_observed_record_interval': largest,
            'equal_monotonic_record_pairs': ties,
            'finding_count': len(findings),
            'finding_counts_by_rule': dict(sorted(Counter(finding.rule_id for finding in findings).items())),
            'clock_mapping': {'tolerance_us': CLOCK_MAPPING_TOLERANCE_US,
                              'offset_range_us': offset_range,
                              'assessment': 'variable' if offset_range > CLOCK_MAPPING_TOLERANCE_US else 'within_tolerance',
                              'wall_clock_regression_count': reversals,
                              'equal_timestamp_wall_clock_difference_pairs': tied_wall_differences,
                              'significant_adjacent_change_count': change_count,
                              'change_examples': changes,
                              'change_examples_truncated': change_count > len(changes)},
            'limitations': list(LIMITATIONS)}


def timeline(findings, records):
    if not records:
        return []
    result, previous = [], None
    first, last = records[0].monotonic_us, records[-1].monotonic_us
    for index, finding in enumerate(findings):
        reference = finding.evidence[0]
        timestamp = reference['monotonic_us']
        if (reference['boot_id'] != records[0].boot_id or not first <= timestamp <= last
                or (previous is not None and timestamp < previous)):
            raise ValueError('Finding outside reconstruction scope or order')
        result.append({'rule_id': finding.rule_id, 'reference': reference, 'finding_index': index,
                       'from_first_visible_record_us': timestamp - first,
                       'before_last_visible_record_us': last - timestamp,
                       'since_previous_finding_us': timestamp - previous if previous is not None else None,
                       'relative_order': ('first_finding' if previous is None else
                                          'unresolved_equal_timestamp' if timestamp == previous else 'monotonic_report_order')})
        previous = timestamp
    return result
