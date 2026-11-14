"""Evidence-backed event rules; no automatic attribution of a freeze or root cause."""
from dataclasses import asdict, dataclass, field
import re

from .commands import Command, CommandRunner
from .journal import BOOT_ID, MAX_RECORDS, SHUTDOWN_REQUEST, UNIT_START_FAILED, boots, entries, validate_window
from .models import report
from .reconstruction import describe, timeline


LIMITATIONS = [
    'Only journal records visible to the current user are examined; no elevation is attempted.',
    'The bounded tail is not the complete boot. Rotation, permission filtering and a freeze can remove final evidence.',
    'Kernel/root compromise can falsify local evidence. Event observations do not establish a root cause.',
    'Timeline order uses boot-local monotonic time; wall-clock timestamps may move backward.',
    'Atop correlation is optional and temporal only; opt-in pstore evidence is not boot-attributed. Complete shutdown verification is not implemented.',
]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    observation: str
    confidence: str
    severity: str
    evidence: list[dict]
    reasoning: str
    thresholds: dict
    limitations: tuple[str, ...]
    recommendations: tuple[str, ...]
    cause_confidence: str = 'Unknown'
    reported_measurements: dict[str, int] = field(default_factory=dict)


# Patterns describe kernel messages, not arbitrary mentions in application output.
KERNEL_RULES = (
    ('kernel.oom', 'Kernel reported an OOM kill',
     r'^(?:Out of memory: Killed process [0-9]+|Memory cgroup out of memory: Killed process [0-9]+)',
     'warning', 'Inspect memory pressure and resource limits around the referenced entry.'),
    ('kernel.panic', 'Kernel reported a panic', r'^Kernel panic - not syncing:',
     'critical', 'Inspect the referenced kernel record and available crash evidence locally.'),
    ('kernel.io_error', 'Kernel reported an I/O error',
     r'^(?:I/O error, dev |blk_update_request: I/O error, dev |Buffer I/O error on dev )',
     'warning', 'Investigate the storage stack and correlated events; do not assume a physical disk failure.'),
    ('kernel.filesystem_error', 'Kernel reported an ext4 error', r'^EXT4-fs error ',
     'warning', 'Inspect filesystem and storage evidence before considering any repair operation.'),
)
# Full-message detector signatures: task names are matched but never copied into findings.
TASK_NAME = r'[^\x00-\x1f\x7f-\x9f]{1,64}'
STALL_RULES = (
    ('kernel.soft_lockup', 'Kernel watchdog reported a soft lockup',
     re.compile(r'watchdog: BUG: soft lockup - CPU#(?P<cpu>[0-9]{1,10}) stuck for (?P<seconds>[0-9]{1,10})s! \['
                + TASK_NAME + r':(?P<pid>[0-9]{1,10})\]\n?'),
     'warning', 'Review nearby scheduling and kernel evidence; do not change watchdog settings based on this report alone.'),
    ('kernel.hard_lockup', 'Kernel watchdog reported a hard lockup',
     re.compile(r'(?:watchdog|NMI watchdog): Watchdog detected hard LOCKUP on cpu (?P<cpu>[0-9]{1,10})\n?'),
     'critical', 'Review nearby kernel records and available crash evidence; a detector report does not prove hardware failure.'),
    ('kernel.hung_task', 'Kernel reported a blocked task',
     re.compile(r'INFO: task ' + TASK_NAME + r':(?P<pid>[0-9]{1,10}) blocked for more than (?P<seconds>[0-9]{1,19}) seconds\.\n?'),
     'warning', 'Review nearby storage, filesystem and scheduling evidence; a blocked task alone does not identify the cause.'),
)


def stall_finding(entry):
    if entry.transport != 'kernel' or entry.message is None:
        return None
    for rule_id, title, pattern, severity, recommendation in STALL_RULES:
        match = pattern.fullmatch(entry.message)
        if not match:
            continue
        fields = {key: int(value) for key, value in match.groupdict().items()}
        if (any(fields.get(key, 0) > 2**31 - 1 for key in ('cpu', 'pid'))
                or ('seconds' in fields and not 1 <= fields['seconds'] <=
                    (2**32 - 1 if rule_id == 'kernel.soft_lockup' else 2**63 - 1))):
            return None
        measurements = {}
        if 'cpu' in fields:
            measurements['reported_cpu_index'] = fields['cpu']
        if 'seconds' in fields:
            key = 'reported_blocked_more_than_seconds' if rule_id == 'kernel.hung_task' else 'reported_stuck_seconds'
            measurements[key] = fields['seconds']
        return Finding(rule_id, title, title + ' in the selected journal tail.',
            'Confirmed', severity, [entry.reference()],
            'A kernel-transport record matches a complete supported detector signature; numeric fields are range-checked.',
            {'minimum_matching_records': 1},
            ('Confirms the recorded detector report, not a proven system-wide freeze, panic or root cause.',
             'Detector configuration, coverage and false positives are not assessed. Missing reports do not exclude stalls.',
             'Reported durations are detector observations, not independently measured timings or configured thresholds.',
             'Task names and process IDs are omitted; CPU indices are reported labels, not verified topology.',
             'Timeline and optional Atop pairing use journal report time, not the full reported stall period.'),
            (recommendation,), reported_measurements=measurements)
    return None


OVERLAY_REUSE = re.compile(
    r'overlayfs: (?P<role>upperdir|workdir) is in-use as upperdir/workdir of another mount, '
    r'accessing files from both mounts will result in undefined behavior\.\n?')


def overlay_reuse_finding(entry):
    if entry.transport != 'kernel' or entry.message is None:
        return None
    match = OVERLAY_REUSE.fullmatch(entry.message)
    if not match:
        return None
    return Finding('kernel.overlay_layer_reuse', 'Kernel reported OverlayFS layer reuse',
        'Kernel reported ' + match['role'] + ' already in use by another mount at the referenced time.',
        'Confirmed', 'warning', [entry.reference()],
        'A kernel-transport record exactly matches the supported OverlayFS shared upper/work directory warning.',
        {'minimum_matching_records': 1},
        ('Confirms the recorded warning, not a currently active conflict, data corruption, system freeze or root cause.',
         'Affected paths, mount namespaces, containers and the responsible service are not identified by this message.',
         'Current mount snapshots can differ from the historical state; distinct path strings do not prove distinct underlying directories.',
         'Upperdir and workdir reports can describe the same mount operation; they are not independent incident counts.',
         'Nearby Docker/container lifecycle events provide temporal context only, not causal attribution.'),
        ('Review the referenced warning locally and compare relevant mount state and namespaces with lifecycle evidence.',
         'Identify the owning workload before any change; do not automatically unmount, delete layers, restart services or disable protection.'))


def analyze(records) -> list[Finding]:
    findings = []
    for entry in records:
        overlay = overlay_reuse_finding(entry)
        if overlay is not None:
            findings.append(overlay)
        stall = stall_finding(entry)
        if stall is not None:
            findings.append(stall)
        if entry.transport == 'kernel' and entry.message is not None:
            for rule_id, title, pattern, severity, recommendation in KERNEL_RULES:
                if re.match(pattern, entry.message):
                    findings.append(Finding(rule_id, title, title + ' in the selected journal tail.',
                        'Confirmed', severity, [entry.reference()],
                        'A kernel-transport record matches a specific event signature.',
                        {'minimum_matching_records': 1},
                        ('Confirms a recorded event, not its cause or responsibility for a reboot.',),
                        (recommendation,)))
        # Trusted journald process metadata prevents an ordinary app's MESSAGE_ID spoof.
        if entry.pid == '1' and entry.comm == 'systemd':
            if entry.message_id == UNIT_START_FAILED:
                findings.append(Finding('systemd.start_job_failed', 'Systemd reported a failed unit start job',
                    'PID 1 recorded the unit-start-job failure message ID.', 'Confirmed', 'warning',
                    [entry.reference()], 'Trusted PID/comm metadata and the structured systemd message ID match.',
                    {'minimum_matching_records': 1}, ('A failed start job is not proof of a system-wide outage.',),
                    ('Inspect the referenced job and its dependencies locally.',)))
            if entry.message_id == SHUTDOWN_REQUEST:
                findings.append(Finding('systemd.shutdown_marker', 'Systemd recorded a shutdown marker',
                    'PID 1 recorded the structured shutdown message ID.', 'Confirmed', 'informational',
                    [entry.reference()], 'Trusted PID/comm metadata and the structured shutdown message ID match.',
                    {'minimum_matching_records': 1}, ('Initiation does not prove that shutdown completed normally.',),
                    ('Correlate with later shutdown and boot evidence before classifying the reboot.',)))
    return findings


def base(command):
    result = report(command, [])
    result.pop('observations')
    result.update(state='unavailable', boots=[], selected_boot=None, findings=[], timeline=[],
                  last_record=None, root_cause='Unknown', shutdown_assessment='Unknown',
                  coverage='unavailable', records_examined=0, record_limit_reached=False,
                  unsupported_messages=0, limitations=list(LIMITATIONS))
    return result


def history(runner=None, *, system_journal=False):
    if type(system_journal) is not bool:
        raise ValueError('Invalid journal scope')
    runner = runner or CommandRunner()
    data = base('history')
    data['journal_scope'] = {'requested': 'system' if system_journal else 'visible',
                             'completeness': 'unknown', 'kernel_records_examined': None,
                             'pid1_systemd_records_examined': None, 'system_evidence_observed': None}
    data['limitations'].append('Journal scope selects accessible sources only; visible scope may contain personal logs only. System scope does not grant access or prove completeness.')
    result = runner.run(Command.JOURNAL_SYSTEM_BOOTS if system_journal else Command.JOURNAL_BOOTS)
    data['boot_listing'] = {'command_state': result.state, 'returncode': result.returncode,
                            'parse_state': 'not_attempted'}
    if result.state != 'completed' or result.returncode != 0:
        data['limitations'].append('The boot-listing command did not succeed; this does not establish absent history or denied access.')
        return data
    try:
        available = boots(result.stdout)
    except ValueError:
        data['boot_listing']['parse_state'] = 'invalid'
        data['limitations'].append('The boot listing was malformed or exceeded safe limits.')
        return data
    data['boot_listing']['parse_state'] = 'valid' if available else 'empty'
    data.update(state='available' if available else 'unavailable',
                coverage='boot_metadata_only' if available else 'unavailable',
                boots=[asdict(boot) for boot in available])
    data['limitations'].append('Boot indices are relative to visible journal history; date strings are not parsed.')
    return data


def diagnose(runner=None, boot_index=None, atop_date=None, *, system_journal=False, search_events=False, boot_id=None, until_us=None, since_us=None):
    validate_window(since_us, until_us)
    if type(search_events) is not bool:
        raise ValueError('Invalid event search option')
    if boot_id is not None:
        if not isinstance(boot_id, str) or not BOOT_ID.fullmatch(boot_id):
            raise ValueError('Invalid boot identity')
        if boot_index is not None:
            raise ValueError('Boot index and identity are mutually exclusive')
    else:
        boot_index = -1 if boot_index is None else boot_index
        if type(boot_index) is not int or not -128 <= boot_index <= 0:
            raise ValueError('Invalid boot index')
    if atop_date is not None:
        from .recordings import recording_date
        recording_date(atop_date)
    runner = runner or CommandRunner()
    data = history(runner, system_journal=system_journal)
    data['atop'] = {'state': 'not_requested' if atop_date is None else 'unavailable',
                    'reason': 'not_requested' if atop_date is None else 'journal_scope_unavailable',
                    'samples': [], 'correlations': []}
    data['command'] = 'diagnose'
    data['boot_selection'] = {'method': 'id' if boot_id is not None else 'index',
                              'requested': boot_id if boot_id is not None else boot_index, 'state': 'unresolved'}
    if since_us is None:
        mode = 'tail' if until_us is None else 'tail_until_realtime'
    else:
        mode = 'tail_since_realtime' if until_us is None else 'bounded_realtime_range'
    data['journal_window'] = {'mode': mode, 'since_realtime_us': since_us,
                               'until_realtime_us': until_us, 'completeness': 'unknown'}
    if since_us is not None:
        data['limitations'].append('The ordinary tail is restricted to the requested receipt-time start boundary. A record cap can still omit earlier records inside the range; targeted searches remain whole-selected-boot.')
    if until_us is not None:
        data['limitations'].append('The ordinary tail ends at the requested journal receipt-time boundary, not the latest boot record. Targeted searches retain their whole-selected-boot scope.')
    data['reconstruction'] = None
    data['journal_collection'] = None
    if search_events:
        from .event_search import unresolved
        data['event_search'] = unresolved(system=system_journal)
    if data['state'] != 'available':
        data['boot_selection']['state'] = 'listing_unavailable'
        data['limitations'].append('Boot selection could not be resolved from the available listing; no fallback boot was queried.')
        return data
    # Resolve the scope-local selector before candidate search or tail collection.
    selected = next((boot for boot in data['boots'] if
                     (boot['boot_id'] == boot_id if boot_id is not None else boot['index'] == boot_index)), None)
    if selected is None:
        data['boot_selection']['state'] = 'not_visible'
        data.update(state='unavailable')
        data['limitations'].append('The requested boot is not visible in the bounded listing for this scope. This does not prove that the boot did not occur.')
        return data
    data['boot_selection']['state'] = 'resolved'
    data.update(selected_boot=selected, state='unavailable', coverage='unavailable')
    if search_events:
        from .event_search import search
        data['event_search'] = search(runner, selected['boot_id'], system=system_journal)
    if since_us is not None:
        result = runner.read_boot_window(selected['boot_id'], since_us, until_us=until_us, system=system_journal)
    elif until_us is not None:
        result = runner.read_boot_until(selected['boot_id'], until_us, system=system_journal)
    elif system_journal:
        result = runner.read_system_boot(selected['boot_id'])
    else:
        result = runner.read_boot(selected['boot_id'])
    data['journal_collection'] = {'command_state': result.state, 'returncode': result.returncode,
                                  'parse_state': 'not_attempted'}
    if result.state != 'completed' or result.returncode != 0:
        data['limitations'].append('Journal collection failed, timed out, exceeded the byte limit or was inaccessible.')
        return data
    try:
        records, limited, unsupported = entries(result.stdout, selected['boot_id'],
            validator=(lambda entry: (since_us is None or entry.realtime_us >= since_us) and
                                    (until_us is None or entry.realtime_us <= until_us))
                      if since_us is not None or until_us is not None else None)
    except ValueError:
        data['journal_collection']['parse_state'] = 'invalid'
        data['limitations'].append('Journal records were malformed, ambiguous or outside the selected boot or requested time boundary.')
        return data
    data['journal_collection']['parse_state'] = 'valid' if records else 'empty'
    kernel_count = sum(entry.transport == 'kernel' for entry in records)
    systemd_count = sum(entry.pid == '1' and entry.comm == 'systemd' for entry in records)
    data['journal_scope'].update(kernel_records_examined=kernel_count,
                                 pid1_systemd_records_examined=systemd_count,
                                 system_evidence_observed=bool(kernel_count or systemd_count))
    if not kernel_count and not systemd_count:
        data['limitations'].append('No kernel or PID 1 systemd records were observed in the retained tail; this does not establish absent system access or a healthy system.')
    findings = analyze(records)
    data.update(state='available' if records else 'unavailable', coverage='bounded_tail',
                records_examined=len(records), record_limit_reached=limited,
                unsupported_messages=unsupported,
                findings=[asdict(finding) for finding in findings],
                last_record=records[-1].reference() if records else None,
                timeline=timeline(findings, records), reconstruction=describe(records, findings, limited, unsupported),
                shutdown_assessment='Marker observed; completion unknown' if any(
                    f.rule_id == 'systemd.shutdown_marker' for f in findings) else 'Unknown')
    data['limitations'].append(f'At most {MAX_RECORDS} tail records are analyzed. No matches is not proof of absence.')
    if limited:
        data['limitations'].append('Earlier entries were omitted by the record cap.')
    if unsupported:
        data['limitations'].append('Some messages were binary, missing or oversized and could not be classified.')
    if not findings:
        data['limitations'].append('No supported event signatures matched; the cause remains unknown.')
    if atop_date is not None:
        from .atop import attach
        attach(data, records, runner, atop_date)
    return data
