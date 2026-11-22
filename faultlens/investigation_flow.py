"""Snapshot-scoped investigation navigation; no collection or evidence persistence."""
from dataclasses import dataclass,replace
import json

from .journal import MAX_REALTIME_US
from .investigation import utc


@dataclass(frozen=True)
class Selection:
    entry: object
    report: dict
    page: int
    row: int=0


def context(data):
    command=data.get('command','uncollected');parts=[command]
    if command=='investigate':
        parts.append({'now':'Problems now','period':'Selected period','before-restart':'Before restart'}[data['mode']])
        window=data['requested_window'];boot=data['boot_filter'].get('resolved')
    elif data.get('inquiry_context'):
        inquiry=data['inquiry_context'];window=inquiry['requested_window']
        parts.append('inquiry '+inquiry['mode']+'; optional boot filter '+str(inquiry['resolved_boot_filter'] or 'none'))
        if inquiry['source_role']=='current_snapshot':parts.append('associated journal window; measurement time is collection time')
        boot=data.get('selected_boot',{}).get('boot_id') if data.get('selected_boot') else None
    else:
        window=data.get('journal_window',{});boot=data.get('selected_boot',{}).get('boot_id') if data.get('selected_boot') else None
    start=window.get('since_realtime_us');end=window.get('until_realtime_us')
    if start is not None or end is not None:parts.append('UTC '+utc(start)+' to '+utc(end))
    if boot:parts.append('boot '+boot)
    if data.get('unit'):parts.append('service '+data['unit'])
    scope=data.get('journal_scope',{}).get('requested')
    if scope:parts.append('journal '+scope+'; completeness unknown')
    parts.append('collected '+str(data.get('collected_at','not established')))
    return ' | '.join(parts)


def selected_scope(selection):
    entry=selection.entry;value=entry.original
    reference=(entry.navigation or {}).get('reference')
    if reference is None and isinstance(value,dict):
        reference=value.get('reference')
        if reference is None and value.get('evidence'):reference=value['evidence'][0]
    if reference is None and isinstance(value,list) and value and isinstance(value[0],dict):reference=value[0].get('reference')
    label=context(selection.report)
    if isinstance(reference,dict) and period(reference) is not None:
        label+=' | selected receipt '+utc(reference['realtime_us'])
        if isinstance(reference.get('boot_id'),str):label+='; source boot '+reference['boot_id']
    return label


def period(reference):
    value=reference.get('realtime_us')
    if type(value) is not int or not 0<=value<=MAX_REALTIME_US:return None
    return max(0,value-60000000),min(MAX_REALTIME_US,value+60000000)


def subject(entry,data):
    """Describe the selected subject without silently making it a query filter."""
    value=entry.original if isinstance(entry.original,dict) else {}
    unit=data.get('unit') or value.get('service') or value.get('unit')
    peer=value.get('reported_peer')
    return '; '.join(part for part in (entry.cells[0],('service '+unit) if unit else '',('reported peer '+peer) if peer else '') if part)


def history_entries(data):
    from .workspace import Entry
    from .investigation import history_detail
    rows=[];summaries={row['boot']['boot_id']:row for row in data.get('summaries',[])}
    # Keep each event with its own immutable boot scope; wall time is not causal ordering.
    for boot in data.get('boots',[]):
        summary=summaries.get(boot['boot_id'])
        for event in summary.get('notable_reports',[]) if summary else ():
            record=event.get('record');reference=event['reference']
            detail={'Recorded message':[event['time']+' | '+event['message_excerpt']],
                'What it means':'A retained report example, not an independent incident or a verified cause. Open its original record or investigate its receipt-time period.',
                'Boot identity':boot['boot_id'],'Source coverage':summary['state']+'; bounded tail; completeness unknown',
                'What you can do':['Investigate the period to compare related sources across accessible boots, or apply an optional boot filter explicitly.'],
                'Evidence limits':summary['limitations']}
            rows.append(Entry((event['title'],event['time'],'Boot '+str(boot['index']),event['message_excerpt'],'Enter opens report and period actions'),
                event,detail,'history_event',navigation={'reference':reference,'record':record}))
        detail=history_detail(summary) if summary else {'Observed':'Boot visible; not examined in this overview',
            'What it means':'This listing does not establish complete history or absent faults.'}
        rows.append(Entry(('Boot '+str(boot['index'])+' — retained source',
            utc(summary['first_record'].get('realtime_us')) if summary and summary.get('first_record') else 'Not examined',
            utc(summary['last_record'].get('realtime_us')) if summary and summary.get('last_record') else 'Not verified',
            summary['state'] if summary else 'Not examined','Enter opens optional boot investigation'),summary or boot,detail,'boot'))
    if not rows:rows.append(Entry(('History evidence unavailable','Not assessed','No boot/event conclusion','Check source coverage','Enter explains'),data,
        {'What it means':'No retained history could be assessed; neither faults nor their absence are established.','Evidence limits':data.get('limitations',[])}))
    return rows


def signals(data,settings):
    from .workspace import Entry,investigation_entries
    rows=[]
    if data is None:return [Entry(('No selected investigation','Not assessed','Open Investigate','Signals reuse retained inquiry evidence'),None,
        {'What it means':'No security or health conclusion follows from an absent inquiry. Signals do not start an independent network scan.'},'investigation_focus')]
    label=context(data)
    rows.append(Entry(('Selected investigation',data.get('state','retained'),label,'Enter continues this inquiry'),data,
        {'What it means':'Signals summarize retained observations and source gaps in this inquiry. They do not collect another Network snapshot or establish an attack/health verdict.','Scope':label},'investigation_focus'))
    scopes=data.get('investigations',[]) if data['command']=='investigate' else [data]
    seen=set()
    for scope in scopes:
        if scope.get('command')=='diagnose':
            for row in investigation_entries(scope):
                if row.kind not in {'finding','journal_record'} or row.cells[0]=='Last retained journal message':continue
                if row.kind=='finding':
                    refs=row.original.get('evidence',[])
                    if refs and all(ref.get('cursor_sha256') for ref in refs):
                        identity=(row.original['rule_id'],json.dumps([{key:ref.get(key) for key in ('source','boot_id','realtime_us','monotonic_us','cursor_sha256')} for ref in refs],sort_keys=True))
                        if identity in seen:continue
                        seen.add(identity)
                rows.append(replace(row,context=scope))
    current=data.get('current',{}) if data['command']=='investigate' else {'network':data} if data['command'] in {'network','security'} else {}
    from .current_views import build
    for source in current.values():
        review=source.get('network_review')
        if review:
            from .network_review import detail
            for value in review['cards']:
                if value['assessment'] in {'Review','Possible'}:
                    rows.append(Entry((value['title'],value['assessment'],'Current '+source['command'],value['observation']),value,detail(value,review),'network_issue',source))
        for row in build(source,'network' if source['command']=='security' else None)['rows']:
            if review and row.assessment in {'Review','Possible'} and (row.kind in {'network_issue','network_issues','interface'} or row.label=='Protocol pressure'):continue
            if row.assessment in {'Critical','Review','Gap','Partial','Possible'}:
                rows.append(Entry((row.label,row.assessment,'Current '+source['command'],row.meaning),row.original,row.detail,row.kind,source))
    if len(rows)==1:
        title='Signals could not be assessed' if data.get('state')=='unavailable' else 'No retained review signal established'
        rows.append(Entry((title,'Unknown',label,'Inspect coverage and evidence'),data,
            {'What it means':'Readable unmatched sources, missing sources and unrequested sources remain distinct. Quiet or unavailable evidence never establishes safety or absence of an incident.'}))
    coverage=data.get('query_coverage',{})
    gaps=[key for key,value in coverage.items() if value['state']!='available' or value['record_limit_reached']]
    state='partial' if gaps and data.get('state')=='available' else data.get('state','retained')
    rows.append(Entry(('Source coverage',state,(str(len(coverage))+' journal queries; '+str(len(gaps))+' incomplete/capped') if coverage else 'See retained source states','Enter explains gaps/caps'),
        data,{'What it means':'Per-source access, caps and unknowns constrain this inquiry. Signals are observations, not distinct incidents.',
              'Coverage':['Query '+key+': '+value['state']+'; retained '+str(value['records_retained'])+('; record cap reached' if value['record_limit_reached'] else '') for key,value in coverage.items()],
              'Evidence limits':data.get('limitations',[])}))
    if len(rows)>128:
        rows=rows[:127]+[Entry(('Signal preview limit reached','Incomplete preview','128-row view bound','Continue in Investigate for all retained sources'),data,
            {'What it means':'Only this derived preview is capped. The original inquiry and all retained sources remain available.'},'investigation_focus')]
    return rows


def evidence(selection,data):
    from .workspace import Entry,source_entries,investigation_entries,workflow_entries
    from .tui_model import Settings
    rows=[]
    if selection is not None:
        chosen=selection.entry
        rows.append(Entry(('Selected evidence',chosen.cells[0],selected_scope(selection),'Fixed to this retained snapshot'),selection.report,
            {'What it means':'This selection remains fixed when another source is opened or refreshed. It is not automatically replaced by a newer report.',
             'Selected subject':subject(chosen,selection.report),'Scope':selected_scope(selection)}))
        rows.append(replace(chosen,cells=(chosen.cells[0],'Open retained selection','Original source context','Enter explains / opens records'),context=selection.report))
        rows.append(Entry(('Return to source','Navigation','Original section; source may now differ','Enter returns'),{'page':selection.page,'row':selection.row},None,'return_source'))
        rows.append(Entry(('Use current inquiry instead','Replace selection','Replace the fixed selection','Enter uses latest retained inquiry'),None,None,'current_evidence'))
    elif data is not None:
        if data['command']=='investigate':rows.extend(workflow_entries(data,Settings(),actions=False))
        elif data['command']=='diagnose':rows.extend(investigation_entries(data))
        else:rows.append(Entry(('Retained source report',data['command'],context(data),'Open readable source rows'),data,{'What it means':'This is a retained source snapshot. Opening it does not collect a replacement.'},'retained_report'))
    if data is not None:
        rows.append(Entry(('Full original report',data['command'],context(data),'Open all retained fields'),data,None,'raw'))
        for entry in source_entries(data):rows.append(Entry((entry.cells[0],entry.cells[1],'Complete retained source','Open original'),entry.original,None,'raw'))
    return rows


PURPOSES={
    'boot_selector':'Optional journal filter. Empty permits accessible boots in the chosen period; it grants no access.',
    'system_journal':'Select accessible system journals. This does not elevate or verify complete system history.',
    'sample_seconds':'Short current CPU/process/network sample duration; not continuous monitoring or a historical baseline.',
    'boot_count':'History source cap: inspect this many visible boots. Report examples do not cover all history.',
    'include_current':'Include current boot in History source selection; first/last retained records are not boot boundaries.',
    'preservation':'Read existing recorder/logging readiness in Health; never changes retention or enables recording.',
    'sockets':'Read numeric current endpoints and permitted reported owners in network context; no reachability probe.',
    'search_events':'Read bounded kernel/service candidates for the inquiry; no match is not an all-clear.',
    'search_ssh':'Read supported SSH password/invalid-user reports; not all key/PAM/MFA or authentication formats.',
    'search_firewall':'Read supported UFW-labelled journal reports; no effective ruleset or final-verdict audit.',
    'atop_date':'Read one existing recording date; no recorder installation, date guessing or verified host/boot identity.',
    'atop_extended':'Read recorded process/network/disk fields; current state does not reconstruct earlier conditions.',
    'pstore':'Read supported live crash fragments with existing access; boot identity and event time unverified.',
    'pstore_archive':'Read the fixed systemd archive independently of live pstore; available archive does not prove a crash.',
    'since_us':'Inclusive receipt-time start with explicit timezone; log receipt time may differ from event time.',
    'until_us':'Inclusive receipt-time end; bounds and missing records do not prove complete incident coverage.',
    'investigation_mode':'Choose problems now, a selected period or before restart. Boot is an optional filter.',
}


def availability(key,snapshots):
    """Explain only cached source state; this function never probes or infers access."""
    inquiry=snapshots.get(5,{})
    if key in {'boot_selector','system_journal','since_us','until_us','investigation_mode'}:
        return 'Retained inquiry: '+context(inquiry) if inquiry else 'No inquiry collected; access and coverage unverified.'
    query={'search_events':'kernel_warnings','search_ssh':'ssh_events','search_firewall':'firewall_events'}.get(key)
    if query:
        source=inquiry.get('query_coverage',{}).get(query)
        return ('Retained query '+query+': '+source['state']+'; '+str(source['records_retained'])+' records'+('; cap reached' if source['record_limit_reached'] else '')
            if source else 'No retained query state; the option alone does not establish usable evidence.')
    if key in {'pstore','pstore_archive','atop_date','atop_extended'}:
        source_key='atop' if key.startswith('atop') else key
        state=inquiry.get('optional_sources',{}).get(source_key)
        if state is None:state=inquiry.get(source_key,{}).get('state')
        return 'Retained optional source '+source_key+': '+str(state) if state is not None else 'No optional source state retained; no availability is assumed.'
    page=4 if key in {'boot_count','include_current'} else 1 if key=='preservation' else 2 if key=='sockets' else 0
    source=inquiry.get('current',{}).get('network') if page==2 else None
    source=source or snapshots.get(page)
    if source is None:return 'No corresponding source snapshot retained; availability unverified.'
    if key=='sockets':return 'Retained socket source: '+source.get('sockets',{}).get('state','not_requested')+'; '+context(source)
    return 'Retained source only: '+context(source)
