"""Domain tables for the UserDock-style workspace; originals are retained by reference."""
from dataclasses import dataclass

from .presentation import (reading,name,observation_view,finding_view,guide,finding_groups,
                           boot_summary_view,boot_summary_label,timeline_label,escaped)
from .tui_model import PAGES,SETTING_KEYS,SETTING_NAMES
from .interface_presentation import interface_view,measurements
from .socket_presentation import row_view as socket_view,row_label as socket_label
from .recording_presentation import recording_view,sample_view,sample_label
from .crash_presentation import source_view,record_view,record_label

TABS=('System','Health','Network','Signals','History','Investigate','Evidence','Settings')


@dataclass(frozen=True)
class Entry:
    cells: tuple
    original: object
    detail: dict | None = None
    kind: str = 'detail'
    context: dict | None = None
    navigation: dict | None = None


def finding_entry(item,source):
    return Entry((item['title'],item['confidence'],source,item['observation']),item,None,'finding')


def source_entries(data):
    result=[]
    for key,title in (('ssh_analysis','SSH reports'),('firewall_analysis','Firewall reports'),
                      ('network_review','Network investigation'),('event_search','Broader event search'),('atop','Recorded resources'),
                      ('pstore','Live crash evidence'),('pstore_archive','Archived crash evidence')):
        if key not in data: continue
        source=data[key]
        result.append(Entry((title,source['state'],key,'Open retained source results'),source,None,'network_issues' if key=='network_review' else key))
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
    from .investigation_flow import signals
    return signals(data,settings)


def page_table(page,data,settings):
    """Return domain columns/rows, never a primary JSON field browser."""
    if page==7:
        from .investigation_flow import PURPOSES
        return ('Collection option','Value','Purpose / access'),[
            Entry((SETTING_NAMES[key],('On' if getattr(settings,key) else 'Off') if type(getattr(settings,key)) is bool
                   else setting_value(settings,key),PURPOSES[key]),key,{'What it means':PURPOSES[key]},'setting') for key in SETTING_KEYS]
    if page==5 and (data is not None and data.get('command')=='investigate' or data is None and settings.investigation_mode):
        return ('Question / evidence','Time / state','Observed evidence / scope','Next step'),workflow_entries(data,settings)
    if page==3:return ('Signal / evidence','State','Retained scope','Next step'),security_entries(data,settings)
    if data is None: return ('Item','Value','Status'),[collection_entry(page)]
    if page in {0,1,2}:
        from .current_views import build
        view=build(data,('status','health','network')[page])
        rows=[Entry((row.label,row.value,row.assessment,row.meaning),row.original,row.detail,row.kind) for row in view['rows']]
        if page==2:rows.append(Entry(('Investigate network logs','Current or selected period','Open inquiry','Review authentication, firewall and service evidence with explicit scope'),None,None,'network_logs'))
        if settings.investigation_mode: rows.append(Entry(('Investigate a problem now','Current + recent evidence','Open inquiry','Enter opens Problems now'),'now',None,'investigation_start'))
        return ('Check','Result','Assessment','Meaning / next step'),rows
    if page==4:
        from .investigation_flow import history_entries
        return ('Reported event / source','Retained UTC','Boot / end UTC','Recorded message / state','Next step'),history_entries(data)
    if page==5:
        entries=[]
        for representative,count,source in finding_groups(data):
            members=_group_members(data,representative,source)
            entries.append(Entry((representative['title'],representative['confidence'],source,
                                  str(count)+' matched reports; not distinct incidents'),members,None,'finding_group'))
        entries=investigation_entries(data)+entries
        entries.append(Entry(('Selected boot chronology',data.get('state','unknown'),'Main retained tail',
            str(data.get('records_examined',0))+' records; not a complete boot'),data,None,'timeline'))
        entries.extend(source_entries(data))
        return ('Finding / evidence','Time / confidence','Recorded message / source','Next step'),entries
    from .investigation_flow import evidence
    return ('Evidence / finding','Time / state','Observed evidence','Next step'),evidence(None,data)


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
    if entry.kind=='retained_report':
        from .tui_model import Settings
        if source['command']=='investigate':return 'Retained inquiry — original snapshot',('Question / evidence','Time / state','Observed evidence','Next step'),workflow_entries(source,Settings(),actions=False)
        page={'status':0,'health':1,'check':1,'network':2,'security':2,'incidents':4,'history':4,'diagnose':5}[source['command']]
        columns,rows=page_table(page,source,Settings())
        return 'Retained report — original snapshot',columns,rows
    if entry.kind=='network_issues':
        from .network_review import detail
        return 'Network observations — attack and cause remain Unknown',('Observation','Assessment','Actual evidence','Next step'),[
            Entry((row['title'],row['assessment'],row['observation'],'Enter explains / opens related evidence'),row,detail(row,source),'network_issue') for row in source['cards']]
    if entry.kind=='network_context':
        labels={'addresses':'Addresses and link flags','routes4':'IPv4 route entries','routes6':'IPv6 route entries','owners':'Reported socket owners'}
        def owned_snapshot(row):
            return dict(row,tcp_listener_rows=sum(value['protocol']=='tcp' and value['state']=='LISTEN' for value in row['rows']),limitations=source['limitations'])
        return 'Independent local network sources',('Source','State','Retained rows','Meaning'),[
            Entry((labels[key],row['state'],str(len(row['rows'])),'Configuration / association, not connectivity'),owned_snapshot(row) if key=='owners' else row,
                  {'What it means':'Independent bounded source; unavailable/empty results do not establish absent configuration or ownership.',
                   'Evidence limits':source['limitations']},'network_addresses' if key=='addresses' else 'network_routes' if key.startswith('routes') else 'sockets') for key,row in source['sources'].items()]
    if entry.kind=='network_addresses':
        return 'Reported addresses / link flags',('Interface','Reported link state','Numeric addresses','Flags'),[
            Entry((row['ifname'],row.get('operstate','UNKNOWN'),', '.join(value['local']+'/'+str(value['prefixlen']) for value in row.get('addr_info',[])),', '.join(row.get('flags',[]))),row,
                  {'Observed':row,'What it means':'Administrative/operational flags and local address assignments only; an UP link does not verify end-to-end service connectivity.'}) for row in source['rows']]
    if entry.kind=='network_routes':
        return 'Reported route entries — policy selection unverified',('Family / table','Destination / type','Gateway / device','Scope'),[
            Entry((str(row['address_family'])+' / '+str(row.get('table','main')),str(row.get('dst','default'))+' / '+str(row.get('type','unicast')),
                   str(row.get('gateway','direct / see next hops'))+' / '+str(row.get('dev','see original')),str(row.get('scope','reported default'))),row,
                  {'Observed':row,'What it means':'A configured route entry is not a verified selected route or remote reachability. Multipath, policy rules, VRFs and other namespaces can change actual forwarding.'}) for row in source['rows']]
    if entry.kind=='network_samples':
        from .interface_presentation import measurements as measurements_for_interface
        def measurements(row):
            interface=next((item['value'] for item in row['observations'] if item['key']=='network.interfaces' and item['value'] is not None),[])
            return [item['interface']+' | '+ '; '.join(measurements_for_interface(item)[:2]) for item in interface]
        return 'Independent measured intervals — not a continuous trace',('Interval','Actual duration','Coverage','Meaning'),[
            Entry((str(row['sample_index']),str(row['sample'].get('elapsed_seconds'))+' s',row['state'],'Open byte/packet rates per interface'),row,
                {'Observed':row['started_at']+' to '+row['finished_at'],'Measurements':measurements(row),
                 'What it means':'Rates belong to each measured interval. No interface sum, sustained-rate or baseline claim is inferred. e retains every protocol counter.'}) for row in source['rows']]
    if entry.kind=='socket_owners':
        return 'Reported owners — sequential associations only',('PID / name','Descriptor','Reported service','Meaning'),[
            Entry((str(row['pid'])+' / '+row['reported_name'],str(row['fd']),row.get('service') or 'Not established','Enter opens reported service when available'),
                  dict(row,unit=row['service']) if row.get('service') else row,
                  {'What it means':'ss-reported owner, with a separate bounded procfs cgroup sample when available. Socket/PID reuse, namespaces and restricted access can prevent or mislead association.'},
                  'service' if row.get('service') else 'detail') for row in source['rows']]
    if entry.kind=='processes':
        from .system_resource_views import process_order,process_detail
        from .presentation import size
        return 'Retained current processes — CPU relative to one logical CPU',('PID','Reported name','CPU (one CPU)','Resident memory'),[
            Entry((str(row['pid']),row['name'],str(row['cpu_percent'])+'%' if row['cpu_percent'] is not None else 'Uncomparable',size(row['rss_bytes'])),
                  row,process_detail(row,source),'process') for row in process_order(source)]
    if entry.kind=='filesystems':
        from .system_resource_views import filesystem_order,filesystem_detail
        def value(row,key):
            return str(row['capacity'][key])+'%' if row['capacity'] is not None and row['capacity'][key] is not None else 'Not assessed'
        return 'Retained mounts — shared capacities must not be summed',('Mount','Type / source state','Space used','Inodes used'),[
            Entry((row['target'],row['filesystem_type']+' / '+row['state'],value(row,'user_used_percent'),value(row,'inode_used_percent')),
                  row,filesystem_detail(row,source),'filesystem') for row in filesystem_order(source)]
    if entry.kind=='service_messages':
        from .service_diagnostics import problem_rows,record_detail
        from .investigation import utc,excerpt
        rows=[]
        for item in problem_rows(data):
            index=item['record_index'];record=data['journal_records'][index]
            detail=record_detail(data,index)
            topic=2 if 'address in use' in item['title'] or 'refused connection' in item['title'] else 0
            rows.append(Entry((item['title'],utc(record['reference']['realtime_us']),
                item['invocation'],excerpt(record['message'],160)),record,detail,'service_message',
                navigation={'record_index':index,'current_page':topic}))
        return 'Service messages — explained / error / other; not independent incidents',('Message / report','Recorded UTC','Invocation scope','Actual message'),rows
    if entry.kind=='scope_details':
        from .tui_model import Settings
        columns,rows=page_table(5,source,Settings())
        return 'Retained journal evidence — source identity in originals',columns,rows
    if entry.kind=='login_sessions':
        from .sessions import detail,source_label,login_label
        return 'Reported terminal-login sessions (coverage unverified)',('Username','Terminal','Login time (UTC)','Source address / reported source'),[
            Entry((row['username'],row['terminal'],login_label(row),source_label(row)),row,detail(row)) for row in source['rows']]
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
                 'What you can do':['Enter opens current service state, retained unit logs, message explanations and next steps. No restart or reset is performed.'],
                 'Evidence limits':source['limitations']},'service') for item in source['rows']]
    if entry.kind=='finding_group':
        return 'Matched reports (not independent incidents)',('Finding','Confidence','Source','Meaning'),[
            finding_entry(row,entry.cells[2]) for row in source]
    if entry.kind=='sockets':
        return 'Local sockets',('Protocol','State','Local endpoint','Peer endpoint'),[
            Entry((row['protocol'].upper(),row['state'],row['local']['original'],row['peer']['original']),row,socket_view(row),'socket')
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
    if data.get('network_review'):
        source=data['network_review']
        rows.append(Entry(('Network investigation',source['state'],str(len(source['cards']))+' concrete observations','Open peer/port reports, alternatives and originals'),source,None,'network_issues'))
    rows.append(answer)
    return rows


def setting_value(settings,key):
    if key=='boot_selector' and not settings.boot_selector: return 'None (all accessible boots)'
    if key=='investigation_mode' and not settings.investigation_mode: return 'Technical single-boot reader'
    if key in {'since_us','until_us'}:
        from .time_window import display
        return display(getattr(settings,key))
    return str(getattr(settings,key) or 'Not selected')


def workflow_entries(data,settings,*,actions=True):
    from dataclasses import replace
    from .tui_model import Settings
    from .workflows import story
    rows=[]
    if actions:
        for mode,label,scope in (('now','Problems now','Current measurements + last 15 minutes'),
                                 ('period','A selected period','Choose start/end; can span restarts'),
                                 ('before-restart','Before restart','Latest visible previous boot')):
            rows.append(Entry((label,'Start inquiry',scope,'Enter; starts without a boot filter'),mode,None,'investigation_start'))
        rows.append(Entry(('Boot filter (optional)',settings.boot_selector or 'None','Clear for all accessible boots','Enter edits filter; no extra access'),'boot_selector',None,'setting'))
    if data is None:return rows+[replace(collection_entry(5),cells=('Collection','Not collected','Choose a question','No conclusion yet'))]
    view=story(data)
    rows.append(Entry(('Investigation answer',data['state'],view['answer'],view['next']),data,
        {'What it means':view['answer'],'Scope':view['scope'],'What you can do':[view['next']],
         'Evidence limits':data['limitations']+view['gaps']}))
    measured=[]
    for name,source in data['current'].items():
        page=1 if name=='health' else 2
        for row in page_table(page,source,Settings())[1]:
            current=replace(row,cells=(row.cells[0],row.cells[1],'Current snapshot: '+row.cells[2],row.cells[3]),context=source)
            (rows if row.cells[2] in {'Critical','Review'} else measured).append(current)
    for child in data['investigations']:
        for row in investigation_entries(child):rows.append(replace(row,context=child))
        rows.append(Entry(('More evidence for this source',child['state'],str(child['records_examined'])+' retained tail records',
                          'Enter for all groups, source coverage and boot-local chronology'),child,None,'scope_details',child))
    rows.extend(measured)
    if data.get('uninterpreted_records'):
        rows.append(Entry(('Uninterpreted retained records',str(data['omitted_boot_scopes'])+' additional boot identities',
            'Interpretation cap reached','Open raw originals; no fault assessment for these partitions'),
            data['uninterpreted_records'],None,'raw'))
    for name,source in data['query_coverage'].items():
        rows.append(Entry(('Query coverage: '+name,source['state'],str(source['records_retained'])+' retained records',
            'Limit reached; evidence incomplete' if source['record_limit_reached'] else source['parse_state']),source,
            {'What it means':'Per-query global cap across boots; readable empty, invalid and unavailable results remain distinct.','Observed':source}))
    for key in ('pstore','pstore_archive','atop'):
        if key in data:rows.append(Entry((key,data[key]['state'],'Independent optional evidence','Enter inspects retained source'),data[key],None,key))
    return rows
