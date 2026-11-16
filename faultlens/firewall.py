"""Kernel firewall-labelled reports; no rule execution or final-verdict inference."""
from collections import Counter
import ipaddress
import re

from .incidents import Finding
from .journal import BOOT_ID, MAX_RECORDS, entries, evidence_record, validate_window
from .parsers import NAME
from .reconstruction import timeline

PREFIX = re.compile(r'\[UFW (?P<label>BLOCK|ALLOW|AUDIT(?: INVALID)?|LIMIT BLOCK)\] (?P<body>[^\x00-\x1f\x7f-\x9f]{1,4096})\n?')
KEY = re.compile(r'[A-Z][A-Z0-9_]{0,31}')
UNIQUE = {'IN', 'OUT', 'SRC', 'DST', 'PROTO', 'SPT', 'DPT', 'TYPE', 'CODE'}
LIMITATIONS = [
    'This query retains at most 500 kernel-tail candidates from the selected boot and receipt bounds. Unrelated kernel records can consume the cap.',
    'Only supported UFW-labelled kernel message forms are classified. Custom nftables/iptables prefixes, NFLOG/ulog and other sources are not interpreted.',
    'Prefixes are configurable text, not proof of active UFW or a verified final packet verdict. LOG can continue through later rules.',
    'Source/destination addresses are packet fields, not authenticated identities. No attack, successful delivery, blocked connection or root cause is established.',
    'Repeated reports, retransmissions and multiple logging rules need not represent distinct packets, flows, clients or incidents.',
    'Logging policy, rate limits, permissions, rotation and missing evidence can hide traffic. An empty query does not establish firewall state or security.',
    'Original candidates, addresses, ports, interfaces and packet fields remain visible locally. Root/kernel compromise or imported logs can falsify evidence.',
    'The filtered timeline is separate from ordinary reconstruction, SSH analysis and Atop pairing. No firewall rules, counters or network probes are queried.',
]


def packet_context(message):
    match = PREFIX.fullmatch(message)
    if not match:
        return None
    tokens = match['body'].split()
    if len(tokens) > 64:
        return None
    fields, selected, flags = [], {}, []
    for token in tokens:
        key, separator, value = token.partition('=')
        if not KEY.fullmatch(key) or len(value) > 256:
            return None
        if separator:
            if key in UNIQUE and key in selected:
                return None
            fields.append((key,value))
            if key in UNIQUE:
                selected[key] = value
        else:
            flags.append(key)
    if not {'IN', 'OUT', 'SRC', 'DST', 'PROTO'} <= selected.keys():
        return None
    if any(value and not NAME.fullmatch(value) for value in (selected['IN'], selected['OUT'])):
        return None
    try:
        src, dst = ipaddress.ip_address(selected['SRC']), ipaddress.ip_address(selected['DST'])
        if src.version != dst.version or '%' in selected['SRC'] or '%' in selected['DST']:
            return None
        protocol = selected['PROTO']
        numeric = {}
        if protocol in {'TCP', 'UDP'}:
            names, maximum = ('SPT', 'DPT'), 65535
        elif protocol in {'ICMP', 'ICMPv6'} and src.version == (4 if protocol == 'ICMP' else 6):
            names, maximum = ('TYPE', 'CODE'), 255
        else:
            return None
        for name in names:
            value = selected.get(name, '')
            if not re.fullmatch(r'[0-9]{1,5}', value) or int(value) > maximum:
                return None
            numeric[name] = int(value)
    except ValueError:
        return None
    return {'reported_label':match['label'], 'input_interface':selected['IN'], 'output_interface':selected['OUT'],
            'source_address':selected['SRC'], 'destination_address':selected['DST'], 'protocol':protocol,
            'numeric_fields':numeric, 'packet_fields':fields, 'flags':flags, 'packet_verdict':'Unknown'}


def classify(entry, candidate_index):
    if entry.transport != 'kernel' or entry.message is None:
        return None
    packet = packet_context(entry.message)
    if packet is None:
        return None
    return Finding('firewall.ufw_packet_report', 'Kernel recorded a UFW-labelled packet report',
        'A kernel record carries the reported label ' + packet['reported_label'] + '.',
        'Confirmed', 'warning' if packet['reported_label'] in {'BLOCK', 'LIMIT BLOCK'} else 'informational',
        [dict(entry.reference(), candidate_index=candidate_index, cursor=entry.cursor, packet=packet)],
        'Kernel transport and a supported complete log form match; addresses, address family and protocol-specific numeric fields are validated.',
        {'minimum_matching_records':1},
        ('A configurable log label is not a verified final verdict, active ruleset or attack.',
         'Repeated reports need not identify distinct packets or flows; source authenticity and coverage remain unverified.'),
        ('Compare the original record with known traffic and locally reviewed policy before drawing a conclusion.',
         'Do not block peers, open ports or change firewall rules automatically from log-prefix observations.'))


def unresolved(*, system=False, since_us=None, until_us=None):
    return {'state':'unavailable', 'reason':'boot_scope_unresolved', 'boot_id':None,
        'requested_scope':'system' if system else 'visible', 'since_realtime_us':since_us, 'until_realtime_us':until_us,
        'query_scope':'selected_boot_kernel_tail', 'candidate_limit':MAX_RECORDS, 'completeness':'unknown',
        'command_state':None, 'returncode':None, 'parse_state':'not_attempted', 'candidates_examined':0,
        'record_limit_reached':False, 'unsupported_messages_in_response':0, 'unclassified_candidates':0,
        'findings':[], 'records':[], 'timeline':[], 'reported_label_counts':{}, 'candidate_window':None,
        'packet_verdict':'Unknown', 'attack_assessment':'Unknown', 'root_cause':'Unknown', 'limitations':list(LIMITATIONS)}


def search(runner, boot_id, *, system=False, since_us=None, until_us=None):
    validate_window(since_us, until_us)
    if not isinstance(boot_id,str) or not BOOT_ID.fullmatch(boot_id) or type(system) is not bool:
        raise ValueError('Invalid firewall evidence scope')
    result = unresolved(system=system, since_us=since_us, until_us=until_us)
    result['boot_id'] = boot_id
    response = runner.read_firewall_candidates(boot_id, system=system, since_us=since_us, until_us=until_us)
    result.update(command_state=response.state, returncode=response.returncode, reason='collection_unavailable')
    if response.state != 'completed' or response.returncode != 0:
        return result
    try:
        records, limited, unsupported = entries(response.stdout, boot_id, validator=lambda entry:
            entry.transport == 'kernel' and (since_us is None or entry.realtime_us >= since_us)
            and (until_us is None or entry.realtime_us <= until_us))
    except ValueError:
        result.update(parse_state='invalid', reason='invalid_or_unexpected_candidates')
        return result
    findings = [value for index, entry in enumerate(records) if (value := classify(entry,index)) is not None]
    positions = timeline(findings, records)
    for position in positions:
        position['reference'] = {key:value for key,value in position['reference'].items() if key != 'packet'}
    result.update(state='available', reason='candidates_examined' if records else 'no_candidates_returned',
        parse_state='valid' if records else 'empty', candidates_examined=len(records), record_limit_reached=limited,
        unsupported_messages_in_response=unsupported, unclassified_candidates=len(records)-len(findings),
        records=[evidence_record(entry) for entry in records], findings=[value.to_dict() for value in findings],
        timeline=positions, reported_label_counts=dict(sorted(Counter(
            value.evidence[0]['packet']['reported_label'] for value in findings).items())),
        candidate_window=None if not records else {'first_candidate':records[0].reference(),'last_candidate':records[-1].reference()})
    return result
