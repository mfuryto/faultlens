"""Evidence-backed event rules; no automatic attribution of a freeze or root cause."""
from dataclasses import asdict, dataclass, field
import re

from .commands import Command, CommandRunner
from .journal import MAX_RECORDS, boots, entries
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


UNIT_START_FAILED = 'be02cf6855d2428ba40df7e9d022f03d'
SHUTDOWN_REQUEST = '98268866d1d54a499c4e98921d93bc40'


def analyze(records) -> list[Finding]:
    findings = []
    for entry in records:
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


def history(runner=None):
    runner = runner or CommandRunner()
    data = base('history')
    result = runner.run(Command.JOURNAL_BOOTS)
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


def diagnose(runner=None, boot_index=-1, atop_date=None):
    if type(boot_index) is not int or not -128 <= boot_index <= 0:
        raise ValueError('Invalid boot index')
    if atop_date is not None:
        from .recordings import recording_date
        recording_date(atop_date)
    runner = runner or CommandRunner()
    data = history(runner)
    data['atop'] = {'state': 'not_requested' if atop_date is None else 'unavailable',
                    'reason': 'not_requested' if atop_date is None else 'journal_scope_unavailable',
                    'samples': [], 'correlations': []}
    data['command'] = 'diagnose'
    data['reconstruction'] = None
    if data['state'] != 'available':
        data['limitations'].append('Boot selection could not be resolved from the available listing; no fallback boot was queried.')
        return data
    selected = next((boot for boot in data['boots'] if boot['index'] == boot_index), None)
    if selected is None:
        data.update(state='unavailable')
        data['limitations'].append('The requested boot is not visible. This does not prove that no earlier boot occurred.')
        return data
    data.update(selected_boot=selected, state='unavailable', coverage='unavailable')
    # Resolve the index to an immutable ID before querying, avoiding reboot/index races.
    result = runner.read_boot(selected['boot_id'])
    if result.state != 'completed' or result.returncode != 0:
        data['limitations'].append('Journal collection failed, timed out, exceeded the byte limit or was inaccessible.')
        return data
    try:
        records, limited, unsupported = entries(result.stdout, selected['boot_id'])
    except ValueError:
        data['limitations'].append('Journal records were malformed, ambiguous or outside the selected boot.')
        return data
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
