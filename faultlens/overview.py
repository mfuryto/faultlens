"""Bounded multi-boot journal summaries from one immutable listing snapshot."""
from .commands import Command, CommandRunner
from .incidents import diagnose, history

MAX_BOOTS = 7


class _ListingSnapshot:
    def __init__(self, runner, command, result):
        self.runner, self.command, self.result = runner, command, result

    def run(self, command):
        if command != self.command:
            raise ValueError('Unexpected overview command')
        return self.result

    def read_boot(self, boot_id):
        return self.runner.read_boot(boot_id)

    def read_system_boot(self, boot_id):
        return self.runner.read_system_boot(boot_id)


def incidents(runner=None, *, boot_count=3, system_journal=False, include_current=False):
    if type(boot_count) is not int or not 1 <= boot_count <= MAX_BOOTS:
        raise ValueError('Invalid overview boot count')
    if type(system_journal) is not bool or type(include_current) is not bool:
        raise ValueError('Invalid overview scope')
    runner = runner or CommandRunner()
    command = Command.JOURNAL_SYSTEM_BOOTS if system_journal else Command.JOURNAL_BOOTS
    snapshot = _ListingSnapshot(runner, command, runner.run(command))
    data = history(snapshot, system_journal=system_journal)
    data.update(command='incidents', coverage='unavailable', summaries=[],
                requested_boot_count=boot_count, include_current=include_current,
                selection_limit_reached=False, selected_boot_count=0,
                root_cause='Unknown', shutdown_assessment='Unknown')
    for key in ('findings', 'timeline', 'selected_boot', 'last_record', 'records_examined',
                'record_limit_reached', 'unsupported_messages'):
        data.pop(key, None)
    data['limitations'].extend([
        'One listing snapshot selects the newest visible previous boots, with current boot included only on request. Indices describe that snapshot.',
        'Each boot is independently queried by immutable identity, with at most 500 retained tail records. Reads are sequential, not atomic.',
        'Finding counts describe recorded reports, not independent incidents. Empty, unavailable or unmatched evidence does not prove a healthy boot.',
        'Monotonic times from different boots are not comparable; boot order follows visible listing indices, not a cross-boot causal timeline.',
        'Shutdown initiation does not prove completion. Missing markers do not prove a crash, freeze or unexpected shutdown.',
        'This overview does not replay Atop or read pstore. Use diagnose with the listed boot ID for detailed findings and explicit optional sources.'])
    if data['state'] != 'available':
        data.update(reason='boot_listing_unavailable')
        return data
    eligible = [boot for boot in data['boots'] if include_current or boot['index'] < 0]
    selected = eligible[:boot_count]
    data.update(selected_boot_count=len(selected), selection_limit_reached=len(eligible) > boot_count)
    if not selected:
        data.update(state='unavailable', reason='no_selected_boots_visible')
        return data
    for boot in selected:
        detail = diagnose(snapshot, boot_id=boot['boot_id'], system_journal=system_journal, show_evidence=True)
        context = detail['reconstruction']
        summary = {
            'boot': dict(boot), 'state': detail['state'],
            'notable_reports': _notable(detail),
            'journal_collection': detail['journal_collection'],
            'records_examined': detail['records_examined'],
            'record_limit_reached': detail['record_limit_reached'],
            'unsupported_messages_in_response': detail['unsupported_messages'],
            'first_record': context.get('first_record') if context else None,
            'last_record': detail['last_record'],
            'finding_count': len(detail['findings']),
            'finding_counts_by_rule': context.get('finding_counts_by_rule', {}) if context else {},
            'shutdown_assessment': detail['shutdown_assessment'], 'root_cause': detail['root_cause'],
            'journal_scope': detail['journal_scope'],
            'completeness': 'unknown', 'limitations': detail['limitations'],
        }
        data['summaries'].append(summary)
        del detail, context
    available = sum(value['state'] == 'available' for value in data['summaries'])
    data.update(state='available' if available == len(selected) else 'partial' if available else 'unavailable',
                coverage='bounded_boot_summaries' if available else 'unavailable',
                reason='selected_boots_examined' if available == len(selected) else 'one_or_more_boots_unavailable')
    return data


def _notable(data):
    from .investigation import examples,linked_records,utc,excerpt
    rows=[]
    for finding,count,source in examples(data)[:3]:
        records=linked_records(data,finding)
        reference=finding['evidence'][0] if finding['evidence'] else {}
        rows.append({'title':finding['title'],'rule_id':finding['rule_id'],'report_count':count,
            'time':utc(reference.get('realtime_us')),
            'message_excerpt':excerpt(records[0]['message']) if records else 'Original message unavailable',
            'reference':reference,'record':records[0] if records else None})
    return rows
