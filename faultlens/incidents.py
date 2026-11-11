"""Evidence-backed event rules; no automatic attribution of a freeze or root cause."""
from dataclasses import asdict, dataclass
import re

from .commands import Command, CommandRunner
from .journal import MAX_RECORDS, boots, entries
from .models import report


LIMITATIONS = [
    'Only journal records visible to the current user are examined; no elevation is attempted.',
    'The bounded tail is not the complete boot. Rotation, permission filtering and a freeze can remove final evidence.',
    'Kernel/root compromise can falsify local evidence. Event observations do not establish a root cause.',
    'Timeline order uses boot-local monotonic time; wall-clock timestamps may move backward.',
    'Atop history, pstore, historical resource correlation and complete shutdown verification are not implemented.',
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
UNIT_START_FAILED = 'be02cf6855d2428ba40df7e9d022f03d'
SHUTDOWN_REQUEST = '98268866d1d54a499c4e98921d93bc40'


def analyze(records) -> list[Finding]:
    findings = []
    for entry in records:
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
    if result.state != 'completed' or result.returncode != 0:
        return data
    try:
        available = boots(result.stdout)
    except ValueError:
        data['limitations'].append('The boot listing was malformed or exceeded safe limits.')
        return data
    data.update(state='available' if available else 'unavailable',
                coverage='boot_metadata_only' if available else 'unavailable',
                boots=[asdict(boot) for boot in available])
    data['limitations'].append('Boot indices are relative to visible journal history; date strings are not parsed.')
    return data


def diagnose(runner=None, boot_index=-1):
    if type(boot_index) is not int or not -128 <= boot_index <= 0:
        raise ValueError('Invalid boot index')
    runner = runner or CommandRunner()
    data = history(runner)
    data['command'] = 'diagnose'
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
                timeline=[{'rule_id': f.rule_id, 'reference': f.evidence[0]} for f in findings],
                shutdown_assessment='Marker observed; completion unknown' if any(
                    f.rule_id == 'systemd.shutdown_marker' for f in findings) else 'Unknown')
    data['limitations'].append(f'At most {MAX_RECORDS} tail records are analyzed. No matches is not proof of absence.')
    if limited:
        data['limitations'].append('Earlier entries were omitted by the record cap.')
    if unsupported:
        data['limitations'].append('Some messages were binary, missing or oversized and could not be classified.')
    if not findings:
        data['limitations'].append('No supported event signatures matched; the cause remains unknown.')
    return data
