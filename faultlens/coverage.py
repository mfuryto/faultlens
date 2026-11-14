"""Bounded coverage hints, never proof of continuous recording or host identity."""
from datetime import datetime, timedelta


def date_gaps(dates):
    if len(dates) > 512:
        raise ValueError('Filename date limit')
    ordered = sorted({datetime.strptime(value, '%Y%m%d').date() for value in dates})
    gaps = []
    for previous, current in zip(ordered, ordered[1:]):
        missing = (current - previous).days - 1
        if missing > 0:
            gaps.append({'first_missing_date': (previous + timedelta(days=1)).strftime('%Y%m%d'),
                         'last_missing_date': (current - timedelta(days=1)).strftime('%Y%m%d'),
                         'missing_days': missing})
    return {'date_ranges': gaps, 'missing_filename_days': sum(gap['missing_days'] for gap in gaps),
            'assessment': 'Possible gaps between observed filename dates only; no inference outside their range.'}


def sample_coverage(values):
    if len(values) > 256:
        raise ValueError('Sample coverage limit')
    gaps, overlaps, resets = [], 0, 0
    for index, current in enumerate(values):
        if current['since_boot']:
            resets += 1
        if index == 0 or current['since_boot'] or values[index - 1]['since_boot']:
            continue
        previous = values[index - 1]
        start = current['timestamp_s'] - current['interval_s']
        if start > previous['timestamp_s']:
            gaps.append({'after_sample_index': previous['sample_index'],
                         'before_sample_index': current['sample_index'],
                         'start_s': previous['timestamp_s'], 'end_s': start,
                         'duration_s': start - previous['timestamp_s'], 'confidence': 'Possible'})
        elif start < previous['timestamp_s']:
            overlaps += 1
    return {'samples_examined': len(values), 'possible_gaps': gaps, 'overlapping_intervals': overlaps,
            'reset_samples': resets,
            'assessment': 'Reported intervals only; no coverage inference before/after samples or across RESET.',
            'limitations': ['Wall-clock changes, restarts and sampling semantics can resemble gaps.',
                            'No gaps found does not prove continuous recording; host and boot remain unverified.']}
