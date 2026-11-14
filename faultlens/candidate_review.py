"""Explain filtered candidates using fixed text and normalized metadata only."""
from collections import Counter, deque

from .journal import MAX_RECORDS

EXAMPLE_LIMIT = 20
PRIORITY_LABELS = ('emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug')
SELECTION = {
    'kernel_warnings': 'Selected by kernel transport and recorded priority 0 through 4, not by a confirmed incident signature.',
    'systemd_events': 'Selected by PID 1/systemd metadata and a supported structured event ID.',
}
REASONS = {
    'no_supported_signature': 'No supported rule matched this candidate. Its meaning and cause remain unclassified; it is not declared benign.',
    'unsupported_message_content': 'Message content is missing, binary or oversized; no supported text signature could be evaluated.',
}
LIMITATIONS = [
    'Recorded priority is source metadata, not an independent severity, health or root-cause assessment.',
    'Unclassified does not mean harmless. Supported signatures cover only a narrow subset of kernel reports.',
    'Only the newest 20 unclassified examples from retained candidates are shown; counts cover all retained candidates.',
    'Candidate indices describe this collection only. References without cursors may not uniquely distinguish equal-timestamp records.',
    'Cursor hashes are evidence identifiers, not journalctl cursor arguments. No raw content or message fingerprints are emitted.',
]


def explain(records, matched, query):
    if query not in SELECTION or len(records) > MAX_RECORDS or len(records) != len(matched):
        raise ValueError('Invalid candidate review scope')
    examples = deque(maxlen=EXAMPLE_LIMIT)
    priorities, reasons = Counter(), Counter()
    matched_count, unavailable_content = 0, 0
    for index, (entry, has_match) in enumerate(zip(records, matched)):
        priority = int(entry.priority) if entry.priority else None
        priorities[str(priority) if priority is not None else 'unspecified'] += 1
        unavailable_content += entry.message is None
        if has_match:
            matched_count += 1
            continue
        reason = 'unsupported_message_content' if entry.message is None else 'no_supported_signature'
        reasons[reason] += 1
        examples.append({'candidate_index': index, 'reference': entry.reference(),
                         'reported_priority': priority,
                         'reported_priority_label': PRIORITY_LABELS[priority] if priority is not None else 'unspecified',
                         'selection_reason': SELECTION[query], 'reason': reason, 'explanation': REASONS[reason],
                         'classification_confidence': 'Unknown', 'cause_confidence': 'Unknown'})
    unclassified_count = len(records) - matched_count
    return {'state': 'available', 'retained_candidates': len(records), 'matched_candidates': matched_count,
            'unclassified_candidates': unclassified_count, 'message_unavailable_candidates': unavailable_content,
            'reported_priority_counts': dict(sorted(priorities.items())),
            'unclassified_reason_counts': dict(sorted(reasons.items())),
            'example_limit': EXAMPLE_LIMIT, 'unclassified_examples': list(examples),
            'unclassified_examples_truncated': unclassified_count > len(examples),
            'limitations': list(LIMITATIONS),
            'recommendations': ['Review referenced entries locally with a trusted journal viewer before assigning meaning; no raw log is displayed or exported automatically.']}
