"""Narrow SSH journal observations; local administrators can inspect identities and original evidence."""
from collections import Counter
from dataclasses import asdict
import ipaddress
import re

from .incidents import Finding
from .journal import BOOT_ID, MAX_RECORDS, entries, evidence_record, validate_window
from .reconstruction import timeline

COMM = {'sshd', 'sshd-session', 'sshd-auth'}
USER = r'[^\s\x00-\x1f\x7f-\x9f]{1,100}'
PEER = r'(?P<peer>[0-9A-Fa-f:.]{1,45}) port (?P<port>[0-9]{1,5})'
PATTERNS = (
    ('ssh.password_failed', 'SSH recorded a failed password authentication', 'warning',
     re.compile(r'Failed password for (?P<invalid>invalid user )?' + r'(?P<username>' + USER + ')' + r' from ' + PEER + r' ssh2(?: \[preauth\])?\n?')),
    ('ssh.password_accepted', 'SSH recorded an accepted password authentication', 'informational',
     re.compile(r'Accepted password for (?P<username>' + USER + ')' + r' from ' + PEER + r' ssh2\n?')),
    ('ssh.invalid_user_report', 'SSH recorded an invalid-user report', 'warning',
     re.compile(r'Invalid user (?P<username>' + USER + ')' + r' from ' + PEER + r'(?: \[preauth\])?\n?')),
)
LIMITATIONS = [
    'Filtered records from the selected boot and requested receipt bounds only; at most 500 retained candidates, completeness unknown.',
    'Only root-UID syslog records from supported sshd process names are selected. Other logging transports, UIDs, names and configurations are excluded.',
    'Trusted journal metadata is a producer constraint, not executable attestation. Root/kernel compromise, log import or forwarding can falsify local evidence.',
    'Narrow password and invalid-user signatures only; keys, PAM details, partial/multifactor results and other authentication methods are not classified.',
    'A failed authentication does not establish brute force or malicious intent; an accepted password does not establish compromise or an authorized full session.',
    'Reports can describe the same connection; counts are not distinct attempts, users, clients, sessions or attacks.',
    'Identities, original messages, process metadata and cursors are available locally. Output can contain sensitive evidence; it is not uploaded or saved automatically.',
    'The filtered timeline is not continuous logging coverage and is separate from main diagnosis, reconstruction and Atop correlation.',
]


def unresolved(*, system=False, since_us=None, until_us=None):
    return {'state': 'unavailable', 'reason': 'boot_scope_unresolved', 'boot_id': None,
            'requested_scope': 'system' if system else 'visible',
            'since_realtime_us': since_us, 'until_realtime_us': until_us,
            'completeness': 'unknown', 'command_state': None, 'returncode': None,
            'candidate_limit': MAX_RECORDS,
            'parse_state': 'not_attempted', 'candidates_examined': 0, 'record_limit_reached': False,
            'unsupported_messages_in_response': 0, 'unclassified_candidates': 0, 'finding_counts_by_rule': {},
            'findings': [], 'records': [], 'timeline': [], 'candidate_window': None, 'attack_assessment': 'Unknown',
            'root_cause': 'Unknown', 'limitations': list(LIMITATIONS)}


def supported_source(entry):
    return entry.uid == '0' and entry.transport == 'syslog' and entry.comm in COMM


def classify(entry, candidate_index=None):
    if not supported_source(entry) or entry.message is None:
        return None
    for rule, title, severity, pattern in PATTERNS:
        match = pattern.fullmatch(entry.message)
        if not match:
            continue
        try:
            ipaddress.ip_address(match['peer'])
        except ValueError:
            continue
        if not 1 <= int(match['port']) <= 65535:
            continue
        return Finding(rule, title, title + ' at the referenced receipt time.',
            'Confirmed', severity, [dict(entry.reference(), candidate_index=candidate_index, cursor=entry.cursor,
                username=match['username'], peer_address=match['peer'], peer_port=int(match['port']))],
            'Trusted root-UID/syslog/process metadata and a complete supported OpenSSH message format match; peer and port syntax are validated.',
            {'minimum_matching_records': 1}, tuple(LIMITATIONS[2:]),
            ('Review original evidence locally and compare expected administrative activity and authentication policy.',
             'Do not block peers, disable accounts or change SSH/firewall settings from these observations alone.'))
    return None


def search(runner, boot_id, *, system=False, since_us=None, until_us=None):
    validate_window(since_us, until_us)
    if not isinstance(boot_id, str) or not BOOT_ID.fullmatch(boot_id) or type(system) is not bool:
        raise ValueError('Invalid SSH evidence scope')
    output = unresolved(system=system, since_us=since_us, until_us=until_us)
    output['boot_id'] = boot_id
    result = runner.read_ssh_candidates(boot_id, system=system, since_us=since_us, until_us=until_us)
    output.update(command_state=result.state, returncode=result.returncode, reason='collection_unavailable')
    if result.state != 'completed' or result.returncode != 0:
        return output
    try:
        records, limited, unsupported = entries(result.stdout, boot_id, validator=lambda entry:
            supported_source(entry) and (since_us is None or entry.realtime_us >= since_us)
            and (until_us is None or entry.realtime_us <= until_us))
    except ValueError:
        output.update(parse_state='invalid', reason='invalid_or_unexpected_candidates')
        return output
    findings = [finding for index, entry in enumerate(records) if (finding := classify(entry, index)) is not None]
    output.update(state='available', reason='candidates_examined' if records else 'no_candidates_returned',
        parse_state='valid' if records else 'empty', candidates_examined=len(records),
        record_limit_reached=limited, unsupported_messages_in_response=unsupported,
        unclassified_candidates=len(records)-len(findings), records=[evidence_record(entry) for entry in records], findings=[asdict(finding) for finding in findings],
        finding_counts_by_rule=dict(sorted(Counter(finding.rule_id for finding in findings).items())),
        timeline=timeline(findings, records), candidate_window=None if not records else {
            'first_candidate': records[0].reference(), 'last_candidate': records[-1].reference()})
    return output
