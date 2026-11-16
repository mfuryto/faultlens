"""Domain tables for the UserDock-style workspace; originals are retained by reference."""
from dataclasses import dataclass

from .presentation import (reading,name,observation_view,finding_view,guide,finding_groups,
                           boot_summary_view,boot_summary_label,timeline_label,escaped)
from .tui_model import PAGES,SETTING_KEYS,SETTING_NAMES
from .interface_presentation import interface_view,measurements
from .socket_presentation import row_view as socket_view,row_label as socket_label
from .recording_presentation import recording_view,sample_view,sample_label
from .crash_presentation import source_view,record_view,record_label

TABS=('System','Health','Network','Signals','History','Diagnostics','Evidence','Settings')


@dataclass(frozen=True)
class Entry:
    cells: tuple
    original: object
    detail: dict | None = None
    kind: str = 'detail'


def finding_entry(item,source):
    return Entry((item['title'],item['confidence'],source,item['observation']),item,None,'finding')


def source_entries(data):
    result=[]
    for key,title in (('ssh_analysis','SSH reports'),('firewall_analysis','Firewall reports'),
                      ('event_search','Broader event search'),('atop','Recorded resources'),
                      ('pstore','Live crash evidence'),('pstore_archive','Archived crash evidence')):
        if key not in data: continue
        source=data[key]
        result.append(Entry((title,source['state'],key,'Open retained source results'),source,None,key))
    return result


def collection_entry(page,state='not_collected'):
    messages={
        'not_collected':('Not collected','No snapshot has been collected for this section.'),
        'loading':('Loading','A bounded read is running. No replacement evidence is available yet.'),
        'cancelled':('Cancelled','Collection was cancelled; no replacement evidence was retained.'),
        'failed':('Unavailable','Collection did not produce a usable report. This does not establish absent events or denied access.'),
    }
    label,meaning=messages.get(state,messages['not_collected'])
    step=('Wait for collection, or use Esc to cancel.' if state=='loading' else
          'Press r to retry using existing access.' if state in {'failed','cancelled'} else
          'Open this source section to load data, or press r to request a read.')
    if page==6:
        label,meaning='No source snapshot','No source report is retained for the evidence browser.'
        step='Open a source section first; Evidence never starts its own collection.'
    detail={'Observed':meaning,'What it means':'No security or health conclusion follows from an absent snapshot.',
            'What you can do':[step]}
    return Entry(('Collection status',label,TABS[page]),None,detail)


def security_entries(data,settings):
    scope=guide(data)
    rows=[Entry(('Current network signals',data.get('state','unknown'),'Live sample',
                 'Short counter sample; attack assessment Unknown'),data,scope)]
    observations=data.get('observations',[])
    readable=sum(item['state']!='unavailable' and item['value'] is not None for item in observations)
    detail={'Observed':str(readable)+' of '+str(len(observations))+' counter observations are readable.',
        'What it means':'This section checks a short current-network-namespace sample. It does not inspect SSH history, effective firewall policy or external reachability.',
        'What you can do':['Open counter readings to inspect unavailable values and the actual sampling interval.',
                           'Review SSH and firewall history separately for the selected boot.'],
        'Evidence limits':['No matched indicator is not an all-clear. Missing or reset counters are not evaluated as zero.']}
    rows.append(Entry(('Counter evidence',str(readable)+'/'+str(len(observations))+' readable','Current namespace',
                       'Enter explains coverage; e opens original readings'),observations,detail))
    if not data.get('findings'):
        label='No supported network indicators matched' if readable else 'No usable network counter evidence'
        rows.append(Entry((label,'Unknown','Live sample','No attack or safety verdict'),data,
            {'Observed':label+'.','What it means':'Missing matches cannot rule out an attack. Short samples can miss intermittent events; unavailable counters cannot establish absence.',
             'What you can do':['Inspect counter coverage and source limitations. Review historical SSH/firewall evidence if relevant.']}))
    if 'sockets' in data:
        socket=data['sockets']
        rows.append(Entry(('Local socket evidence',socket['state'],'ss / current namespace',
                           str(len(socket['rows']))+(' retained row' if len(socket['rows'])==1 else ' retained rows')+'; reachability unverified'),socket,None,'sockets'))
    else:
        rows.append(Entry(('Local socket evidence','Not requested','Current namespace','Enable socket endpoints in Settings'),None,
            {'Observed':'Socket evidence was not requested.','What it means':'No socket or reachability conclusion is available.',
             'What you can do':['Enable socket endpoints in Settings and refresh this section.']}))
    requested={'boot_selector':settings.boot_selector,'journal_scope':'system' if settings.system_journal else 'visible',
               'search_ssh':settings.search_ssh,'search_firewall':settings.search_firewall}
    rows.append(Entry(('SSH and firewall history','Separate query','Selected boot '+settings.boot_selector,
                       'SSH '+('On' if settings.search_ssh else 'Off')+' / firewall '+('On' if settings.search_firewall else 'Off')+'; Enter opens Diagnostics'),requested,None,'diagnostics_link'))
    return rows


def page_table(page,data,settings):
    """Return domain columns/rows, never a primary JSON field browser."""
    if page==7:
        return ('Collection option','Value','Scope'),[
            Entry((SETTING_NAMES[key],('On' if getattr(settings,key) else 'Off') if type(getattr(settings,key)) is bool
                   else str(getattr(settings,key) or 'Not selected'),'Session only'),key,None,'setting') for key in SETTING_KEYS]
    if data is None: return ('Item','Value','Status'),[collection_entry(page)]
    if page in {0,1,2}:
        from .current_views import build
        view=build(data,('status','health','network')[page])
        return ('Check','Result','Assessment','Meaning / next step'),[
            Entry((row.label,row.value,row.assessment,row.meaning),row.original,row.detail,row.kind) for row in view['rows']]
    if page==4:
        from .investigation import history_detail,utc
        summaries={row['boot']['boot_id']:row for row in data.get('summaries',[])}
        rows=[]
        for boot in data.get('boots',[]):
            summary=summaries.get(boot['boot_id'])
            detail=history_detail(summary) if summary else {'Observed':'Boot visible; not examined in this overview',
                'What it means':'Select this boot to investigate it; this listing does not establish complete history.'}
            first=summary.get('first_record') if summary else None
            last=summary.get('last_record') if summary else None
            reports=summary.get('notable_reports',[]) if summary else []
            rows.append(Entry(('Boot '+str(boot['index']),utc(first.get('realtime_us')) if first else 'Not examined',
                utc(last.get('realtime_us')) if last else 'Not verified',
                reports[0]['title'] if reports else 'No supported match' if summary and summary['state']=='available' else 'Evidence not assessed',
                'Enter to investigate'),summary or boot,detail,'boot'))
        if not rows:
            empty=collection_entry(4,'failed')
            rows.append(Entry((*empty.cells,'No boot assessed','Check journal scope'),empty.original,empty.detail))
        return ('Boot','First retained UTC','Last retained UTC','Reported problem','Next step'),rows
    if page in {3,5}:
        entries=[]
        for representative,count,source in finding_groups(data):
            members=_group_members(data,representative,source)
            entries.append(Entry((representative['title'],representative['confidence'],source,
                                  str(count)+' matched reports; not distinct incidents'),members,None,'finding_group'))
        if page==3: entries.extend(security_entries(data,settings))
        if page==5:
            entries=investigation_entries(data)+entries
            entries.append(Entry(('Selected boot chronology',data.get('state','unknown'),'Main retained tail',
                str(data.get('records_examined',0))+' records; not a complete boot'),data,None,'timeline'))
        entries.extend(source_entries(data))
        return (('Finding / evidence','Time / confidence','Recorded message / source','Next step') if page==5 else ('Finding / evidence','Confidence / state','Source','Meaning')),entries
    # Evidence is an explicit, secondary entry to complete source originals.
    entries=investigation_entries(data) if data['command']=='diagnose' else []
    entries.append(Entry(('Full original report',data['command'],'All retained fields','Open original'),data,None,'raw'))
    for entry in source_entries(data):
        entries.append(Entry((entry.cells[0],entry.cells[1],'Complete retained source','Open original'),entry.original,None,'raw'))
    return ('Evidence / finding','Time / state','Observed evidence','Next step'),entries


def _group_members(data,representative,source):
    if source=='main': values=data.get('findings',[])
    elif source.startswith('event_search.'):
        query=source.removeprefix('event_search.')
        values=next((v['findings'] for v in data['event_search']['queries'] if v['query']==query),[])
    else: values=data[source]['findings']
    return [item for item in values if (item['rule_id'],item['confidence'],item['severity'])==
            (representative['rule_id'],representative['confidence'],representative['severity'])]


def source_table(entry,data):
    source=entry.original
    if entry.kind=='observations':
        from .current_views import observation
        values=[observation(item) for item in source]
        rank={'Critical':0,'Review':1,'Gap':2,'Measured':3,'Info':4}
        values.sort(key=lambda item:rank[item.assessment])
        return entry.cells[0],('Reading','Value','Assessment','Meaning'),[
            Entry((item.label,item.value,item.assessment,item.meaning),item.original,item.detail,'observation') for item in values]
    if entry.kind=='interfaces':
        from .current_views import interface
        values=[interface(item,data.get('sample',{})) for item in source]
        return 'All retained interfaces',('Interface','Rates','Assessment','Meaning'),[
            Entry((item.label,item.value,item.assessment,item.meaning),item.original,item.detail) for item in values]
    if entry.kind=='failed_services':
        return 'Observed failed service units',('Service unit','State','Description'),[
            Entry((item['unit'],item['active'],item['description']),item,
                {'Observed':item['unit']+' was listed as failed.',
                 'What it means':'System-manager service state only; service impact and root cause are not established.',
                 'What you can do':['Review this unit and its logs with existing access. No restart or reset is performed.'],
                 'Evidence limits':source['limitations']}) for item in source['rows']]
    if entry.kind=='finding_group':
        return 'Matched reports (not independent incidents)',('Finding','Confidence','Source','Meaning'),[
            finding_entry(row,entry.cells[2]) for row in source]
    if entry.kind=='sockets':
        return 'Local sockets',('Protocol','State','Local endpoint','Peer endpoint'),[
            Entry((row['protocol'].upper(),row['state'],row['local']['original'],row['peer']['original']),row,socket_view(row))
            for row in source['rows']]
    if entry.kind=='atop':
        return 'Recorded resource samples',('Sample','UTC interval','Scope'),[
            Entry((str(row['sample_index']),sample_label(row),'Host/boot unverified'),row,sample_view(row)) for row in source['samples']]
    if entry.kind in {'pstore','pstore_archive'}:
        return 'Crash fragments',('Fragment','Signature confidence','Relative path'),[
            Entry((record_label(row),row['confidence'],row.get('relative_path') or 'Not retained'),row,record_view(row)) for row in source['records']]
    if entry.kind=='event_search':
        return 'Broader journal searches',('Search','State','Candidate records','Matched reports'),[
            Entry((row['query'],row['state'],str(row['candidates_examined']),str(len(row['findings']))),row,None,'analysis') for row in source['queries']]
    if entry.kind=='timeline':
        from .evidence_links import timeline_finding
        entries=[]
        for row in source.get('timeline',[]):
            finding=timeline_finding(data,source['timeline'],row)
            detail=finding_view(finding) if finding is not None else {
                'Meaning':'Reference could not be resolved in its original source; no finding was guessed.'}
            detail['Timeline position']=row
            entries.append(Entry((timeline_label(row),row['rule_id'],row['relative_order']),
                                 finding if finding is not None else row,detail,'finding' if finding is not None else 'detail'))
        return 'Selected boot timeline',('Position','Rule','Order'),entries
    return 'Recorded findings',('Finding','Confidence','Source','Meaning'),[
        Entry((row['title'],row['confidence'],entry.cells[0],row['observation']),row,finding_view(row),'finding') for row in source.get('findings',[])]


def detail_text(detail):
    """Prose only; nested originals are opened separately rather than serialized here."""
    lines=[]
    for key,value in detail.items():
        if key in {'Technical details','Original content','Signature line references'}: continue
        lines.append(key)
        if isinstance(value,list): lines.extend('  - '+escaped(v) for v in value if not isinstance(v,(dict,list)))
        elif not isinstance(value,dict): lines.append('  '+escaped(value))
        lines.append('')
    return '\n'.join(lines)


def investigation_entries(data):
    from .investigation import story,examples,finding_detail,excerpt,utc,unclassified_records
    view=story(data)
    answer=Entry(('Investigation answer',data.get('state','unknown'),view['answer'],'Enter for next steps'),data,
        {'Observed':view['answer'],'What you can do':[view['next']],
         'Selected evidence':view['scope'],'Cause':view['cause'],'Last evidence':view['ending'],
         'Missing coverage':view['gaps']})
    rows=[]
    for finding,count,source in examples(data):
        detail=finding_detail(data,finding)
        rows.append(Entry((finding['title'],detail['Recorded evidence'][0].split(' | ',1)[0],
            detail['Recorded evidence'][0].split(' | ',1)[-1],str(count)+' reports; Enter explains'),
            finding,detail,'finding'))
    for record in unclassified_records(data):
        rows.append(Entry(('Unclassified warning/event',utc(record['reference'].get('realtime_us')),
            excerpt(record['message']),'Enter reads actual message'),record,
            {'What it means':'Selected by source metadata; no supported fault meaning or cause was assigned.'},'journal_record'))
    records=data.get('journal_records',[])
    if records:
        last=records[-1]
        rows.append(Entry(('Last retained journal message',utc(last['reference'].get('realtime_us')),
            excerpt(last['message']),'Later conditions unknown'),last,
            {'Recorded message':[utc(last['reference'].get('realtime_us'))+' | '+excerpt(last['message'],2048)],
             'What it means':view['ending'],'What you can do':[view['next']]},'journal_record'))
    rows.append(answer)
    return rows
