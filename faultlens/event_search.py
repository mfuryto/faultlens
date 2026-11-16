"""Two fixed bounded candidate queries over one immutable accessible journal boot."""
from dataclasses import asdict

from .candidate_review import explain
from .journal import BOOT_ID, MAX_RECORDS, SHUTDOWN_REQUEST, UNIT_START_FAILED, entries, evidence_record, validate_window
from .reconstruction import timeline

QUERIES = ('kernel_warnings', 'systemd_events')
LIMITATIONS = [
    'Filtered candidates from the accessible selected boot only; coverage and search completeness remain unknown.',
    'Each query retains at most 500 candidates. Other kernel warnings can consume the cap; lower-priority kernel reports are excluded.',
    'A completed empty query or no supported findings does not prove no earlier events, complete access or system health.',
    'Candidate timestamps are journal receipt times; intervals between filtered records are not log gaps or downtime.',
    'Results may repeat the ordinary tail or each other; they are separate views, not independent corroboration or incident counts.',
    'Main diagnosis, reconstruction, shutdown assessment and optional Atop pairing remain scoped to the ordinary tail.',
]


def unresolved(*, system=False, since_us=None, until_us=None):
    validate_window(since_us,until_us)
    if type(system) is not bool:
        raise ValueError('Invalid event search scope')
    return {'state': 'unavailable', 'reason': 'boot_scope_unresolved',
            'requested_scope': 'system' if system else 'visible', 'boot_id': None,
            'search_range': 'bounded_receipt_time_candidates' if since_us is not None or until_us is not None else 'accessible_selected_boot_filtered_candidates',
            'requested_window':{'since_realtime_us':since_us,'until_realtime_us':until_us}, 'completeness': 'unknown',
            'candidate_limit_per_query': MAX_RECORDS, 'queries': [],
            'root_cause': 'Unknown', 'limitations': list(LIMITATIONS)}


def _valid_candidate(entry, query):
    if query == 'kernel_warnings':
        return entry.transport == 'kernel' and entry.priority in {'0', '1', '2', '3', '4'}
    return (entry.pid == '1' and entry.comm == 'systemd'
            and entry.message_id in {UNIT_START_FAILED, SHUTDOWN_REQUEST})


def search(runner, boot_id, *, system=False, show_evidence=False, since_us=None, until_us=None):
    validate_window(since_us,until_us)
    if type(show_evidence) is not bool:
        raise ValueError('Invalid evidence view option')
    if not isinstance(boot_id, str) or not BOOT_ID.fullmatch(boot_id) or type(system) is not bool:
        raise ValueError('Invalid event search scope')
    from .incidents import analyze
    results = []
    for query in QUERIES:
        options={'since_us':since_us,'until_us':until_us} if since_us is not None or until_us is not None else {}
        result = runner.read_event_candidates(boot_id, query, system=system,**options)
        item = {'query': query, 'state': 'unavailable', 'command_state': result.state,
                'returncode': result.returncode, 'parse_state': 'not_attempted', 'candidates_examined': 0,
                'record_limit_reached': False, 'unsupported_messages_in_response': 0,
                'candidate_window': None, 'findings': [], 'timeline': [], 'candidate_review': None}
        if show_evidence:
            item['records'] = []
        results.append(item)
        if result.state != 'completed' or result.returncode != 0:
            item['reason'] = 'collection_unavailable'
            continue
        try:
            records, limited, unsupported = entries(result.stdout, boot_id,
                                                     validator=lambda entry: _valid_candidate(entry, query)
                                                        and (since_us is None or entry.realtime_us>=since_us)
                                                        and (until_us is None or entry.realtime_us<=until_us))
        except ValueError:
            item.update(parse_state='invalid', reason='invalid_or_unexpected_candidates')
            continue
        if show_evidence:
            item['records'] = [evidence_record(entry) for entry in records]
        findings, matched = [], []
        for entry in records:
            matches = [finding for finding in analyze([entry])
                       if finding.rule_id.startswith('kernel.' if query == 'kernel_warnings' else 'systemd.')]
            findings.extend(matches)
            matched.append(bool(matches))
        window = None if not records else {'first_candidate': records[0].reference(),
                  'last_candidate': records[-1].reference(),
                  'monotonic_candidate_span_us': records[-1].monotonic_us - records[0].monotonic_us}
        item.update(state='available', parse_state='valid' if records else 'empty',
                    reason='candidates_examined' if records else 'no_candidates_returned',
                    candidates_examined=len(records), record_limit_reached=limited,
                    unsupported_messages_in_response=unsupported, candidate_window=window,
                    findings=[asdict(finding) for finding in findings], timeline=timeline(findings, records),
                    candidate_review=explain(records, matched, query))
    completed = sum(item['state'] == 'available' for item in results)
    output = unresolved(system=system,since_us=since_us,until_us=until_us)
    output.update(state='available' if completed == 2 else 'partial' if completed else 'unavailable',
                  reason='queries_completed' if completed == 2 else 'one_or_more_queries_unavailable',
                  boot_id=boot_id, queries=results)
    return output
