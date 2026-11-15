"""Readable retained Atop coverage and samples; no replay, attribution or new analysis."""
from datetime import datetime,timezone

from .presentation import duration,size

REASONS={
    'journal_scope_unavailable':'No usable selected journal tail was available to anchor the replay window; this does not prove that recordings are absent.',
    'ambiguous_journal_clock_mapping':'Journal wall-clock mapping varied too much to anchor replay safely. A recording was not guessed from these times.',
    'recording_collection_unavailable':'The requested recording could not be collected within the existing access, format or resource limits. The failure does not identify which condition caused it.',
    'unsupported_or_ambiguous_samples':'The recording output was unsupported or ambiguous; no successful sample prefix was retained.',
    'no_samples_in_window':'No usable samples were retained in the requested replay window. This does not prove the recording is empty outside that window.',
}
LIMITS=[
    'Recording host/boot identity and authenticity remain unverified; a temporal overlap is not a cause.',
    'CPU shares describe recorded intervals, not instantaneous peaks. Memory free/cache are snapshots, not MemAvailable or pressure evidence.',
    'Reported gaps can reflect clock changes, restarts or sampling semantics. No gaps does not prove continuous recording.',
    'No coverage is inferred before/after retained samples or across RESET. Readable values are rounded; exact values remain in technical details.',
]


def utc_time(value):
    try: return datetime.fromtimestamp(value,timezone.utc).isoformat()
    except (ValueError,OverflowError,OSError): return str(value)+' Unix seconds'


def recording_view(source):
    state=source['state']
    meaning=[]
    if state=='not_requested':
        observed='Historical recording not requested'
        meaning.append('Replay is optional. No missing recording or tool is inferred from an unrequested feature.')
    elif state!='available':
        observed='Historical recording unavailable'
        meaning.append(REASONS.get(source.get('reason'),'The requested source did not provide a usable recording window; absence of an incident or recording is not established.'))
    else:
        observed=str(len(source['samples']))+' retained recording samples'
        coverage=source.get('coverage')
        if coverage:
            meaning.append('Reported interval coverage: '+str(len(coverage['possible_gaps']))+' possible gaps, '
                +str(coverage['overlapping_intervals'])+' overlapping intervals, '+str(coverage['reset_samples'])+' RESET samples.')
        else:
            meaning.append('Interval coverage was not established; no continuous history is inferred.')
        meaning.append('A bounded replay window from one recording was examined. Host/boot identity remains unverified.')
        if source.get('correlation_limit_reached'):
            meaning.append('The temporal-overlap reference limit was reached; the displayed relationships are not a complete list.')
    if 'recording_date' in source:
        meaning.append('Requested recording filename date: '+source['recording_date']+'. This selects a recording, not a verified event date or boot identity.')
    if 'window_start_s' in source and 'window_end_s' in source:
        meaning.append('Requested replay window (UTC): '+utc_time(source['window_start_s'])+' to '+utc_time(source['window_end_s'])+'. This is not an incident boundary.')
    return {'Observed':observed,'What it means':meaning,'What you can do':[
        'Review the requested recording date, window and coverage in technical details before relating samples to a symptom.',
        'Use existing recording/access settings only; this view does not install a recorder, replay another date or change retention.'],
        'Evidence limits':list(LIMITS),'Technical details':source}


def sample_label(sample):
    timestamp=utc_time(sample['timestamp_s'])
    return ('Sample '+str(sample['sample_index'])+' | '+timestamp+' | '+duration(sample['interval_s'])
            +(' | RESET aggregate' if sample['since_boot'] else ' recorded interval'))


def sample_measurements(sample):
    values=[]
    for key,label in (('cpu_execution_percent','CPU execution'),('cpu_iowait_percent','CPU iowait'),
                      ('cpu_steal_percent','CPU steal'),('cpu_busy_percent','Legacy CPU busy (includes steal)')):
        value=sample.get(key)
        values.append(label+': '+('Not comparable' if sample['since_boot'] or value is None else f'{value:.2f}%'))
    for key,label in (('memory_total_bytes','Total RAM'),('memory_free_bytes','Free RAM snapshot'),
                      ('memory_cache_bytes','Cache snapshot'),('swap_used_bytes','Swap used snapshot'),
                      ('swap_total_bytes','Total swap')):
        value=sample.get(key)
        values.append(label+': '+('Not available' if value is None else size(value)))
    return values


def sample_view(sample):
    meaning=['CPU execution excludes idle, iowait and steal; legacy busy includes steal. Iowait is not disk utilization, and steal does not prove provider contention.',
             'Memory/cache/swap describe the sample end, not necessarily the event time. Swap use alone does not establish current pressure.']
    if sample['since_boot']:
        meaning.insert(0,'This RESET aggregate is not a comparable recorded interval. No interval CPU percentage is inferred.')
    return {'Observed':sample_label(sample),'Recorded host':sample.get('recorded_hostname','Not retained'),
            'Measurements':sample_measurements(sample),'What it means':meaning,
            'What you can do':['Compare retained adjacent samples and original source lines before attributing a workload change or cause.'],
            'Evidence limits':list(LIMITS),'Technical details':sample}
