"""Operator decisions for current views; retain evidence without resampling or mutation."""
from dataclasses import dataclass,field

from .presentation import name,reading,observation_view,duration
from .interface_presentation import interface_view,measurements


@dataclass(frozen=True)
class Decision:
    label:str
    value:str
    assessment:str
    meaning:str
    original:object
    detail:dict=field(default_factory=dict)
    kind:str='observation'

    def __post_init__(self):
        # Copy view metadata only; original evidence and nested technical references stay intact.
        object.__setattr__(self,'detail',{**self.detail,'View assessment':self.assessment,
            'What it means':self.meaning})


def observation(item):
    detail=observation_view(item)
    value=reading(item);assessment='Measured';meaning=detail['What it means']
    if item['state']=='unavailable': assessment='Gap'
    elif item['value'] is None:
        if 'No explicit assignment' in item.get('explanation','') or item['key'].startswith('atop.config.'):
            value='Default not verified';assessment='Info'
            meaning='No effective value was established; service defaults or overrides may apply. No configuration change follows from this alone.'
        elif 'unsupported expression' in item.get('explanation',''):
            value='Unsupported expression';assessment='Gap';meaning=item['explanation']
        else: value='Not verified';assessment='Gap'
    elif item['state']=='critical': assessment='Critical'
    elif item['state']=='warning': assessment='Review'
    elif item['key'].startswith('dependency.') or item['state']=='unknown': assessment='Info'
    if item['key']=='cpu.load_average' and isinstance(item['value'],list):
        value=' / '.join(str(v) for v in item['value'])
    if item['key']=='cpu.busy' and type(item['value']) in {float,int} and item['value']>=90 and item['state'] not in {'warning','critical'}:
        assessment='Review'
        meaning='CPU activity is at least 90% in this short sample. Repeat during the symptom; this does not establish sustained overload or a responsible process.'
        detail={**detail,'View threshold':'Short-sample review hint: CPU activity >=90%; source confidence/state are unchanged.'}
    if (item['key'] in {'network.tcp.SyncookiesSent','network.tcp.ListenOverflows','network.tcp.ListenDrops',
                        'network.udp.InErrors','network.udp.RcvbufErrors','network.udp.SndbufErrors'}
            and isinstance(item['value'],dict) and item['value'].get('delta',0)>0):
        assessment='Review'
        detail={**detail,'View threshold':'Supported pressure/error counter delta >0; overlapping counts and legitimate causes remain possible.'}
    if item['key']=='journal.previous_boots':
        meaning='Boot listing visible to this account only; usable system/kernel history is not verified. Use explicit system-journal scope in History/Diagnostics for server evidence.'
    if item['key']=='journal.config.storage' and item['value'] is not None:
        meaning='Configuration assignment only; the effective running storage mode and usable retained history remain unverified.'
    detail={**detail,'Observed':value,'What it means':meaning,'View assessment':assessment}
    labels={'cpu.load_average':'Load (1/5/15 min)','filesystem.root.user_used':'Root space used',
            'filesystem.root.used':'Root space used','services.system_state':'Service manager','atop.service_active':'Atop recorder',
            'journal.config.storage':'Journal storage hint'}
    return Decision(labels.get(item['key'],name(item)),value,assessment,meaning,item,detail)


def group(label,items,meaning,*,value=None,assessment='Info'):
    return Decision(label,value or str(len(items))+' retained readings',assessment,meaning,items,
        {'Observed':value or str(len(items))+' retained readings','What it means':meaning},'observations')


def _operational(data):
    keys={'cpu.busy','cpu.load_average','memory.used','swap.used','filesystem.root.user_used','services.system_state','system.uptime'}
    by_key={item['key']:item for item in data.get('observations',[])}
    if 'filesystem.root.user_used' not in by_key or by_key['filesystem.root.user_used']['value'] is None:
        keys.discard('filesystem.root.user_used'); keys.add('filesystem.root.used')
    items=[observation(item) for item in data.get('observations',[]) if item['key'] in keys]
    if not items and data.get('observations'): items=[observation(data['observations'][0])]
    rank={'Critical':0,'Review':1,'Gap':2,'Measured':3,'Info':4}
    return sorted(items,key=lambda item:rank[item.assessment])


def _all(data):
    items=data.get('observations',[])
    gaps=sum(observation(item).assessment=='Gap' for item in items)
    return group('All readings',items,
        'Includes original measurements, tool purposes and source limitations. Availability is not a health verdict.',
        value=str(len(items))+' readings; '+str(gaps)+' gaps',assessment='Partial' if gaps else 'Info')


def _system(data):
    rows=_operational(data)
    from .system_resource_views import decisions
    rows.extend(decisions(data))
    rank={'Critical':0,'Review':1,'Gap':2,'Partial':3,'Measured':4,'Info':5}
    rows.sort(key=lambda row:rank[row.assessment])
    review=sum(item.assessment in {'Critical','Review'} for item in rows)
    gaps=sum(item.assessment in {'Gap','Partial'} for item in rows)
    summary=('Review the highlighted capacity or service readings.' if review else
             'Current operational readings are incomplete.' if gaps or not rows else
             'No configured capacity or service warning was observed in this snapshot.')
    step=('Inspect highlighted readings before making changes; repeat measurements during the symptom.' if review else
          'Open source gaps to see what could not be assessed.' if gaps or not rows else
          'No immediate change is indicated by these readings; use History/Diagnostics for an earlier problem.')
    source=data.get('login_sessions')
    if source is not None:
        available=source['state'] in {'available','partial'};count=len(source['rows'])
        value=(str(count)+' reported session'+('' if count==1 else 's')) if count else 'No login records reported' if available else 'Could not be assessed'
        meaning=('Enter for usernames, terminals, UTC login times and reported sources. Records may be stale or incomplete.' if count else
            'The source returned no login records. This does not establish that nobody is logged in.' if available else
            'Login records were unavailable or unsupported; no empty-success result is inferred.')
        if source.get('fallback_used'):meaning+=' Fallback accounting source used; logind was unavailable or returned no records.'
        rows.append(Decision('Logged-in users',value,'Partial' if source['state']=='partial' else 'Measured' if count else 'Info' if available else 'Gap',meaning,source,
            {'Collection source':source['source'],'What it means':meaning,'What you can do':['Open the session rows and compare expected administrative activity; no session is modified.'],
             'Evidence limits':source['limitations']},'login_sessions'))
    return summary,step,rows+[_all(data)]


def _health(data):
    observations=data.get('observations',[]);by_key={item['key']:item for item in observations}
    operational=_operational(data) if data['command']=='health' else []
    reviews=[row for row in operational if row.assessment in {'Critical','Review'}]
    missing=[row.original for row in operational if row.assessment=='Gap']
    rows=[]
    if operational:
        rows.append(group('Operational checks',[row.original for row in reviews],
            'These capacity/manager observations merit review; counts are readings, not independent failures.',
            value=str(len(reviews))+' review; '+str(len(missing))+' unknown',
            assessment='Review' if reviews else 'Gap' if missing else 'Measured'))
        rows[-1]=Decision(rows[-1].label,rows[-1].value,rows[-1].assessment,rows[-1].meaning,
                          [row.original for row in operational],rows[-1].detail,'observations')
    else:
        rows.append(Decision('Operational snapshot','Not collected','Info',
            'check inspects diagnostic readiness. Use health or System for current resource/service readings.',None,
            {'What it means':'No operational snapshot is included in this readiness-only report.','What you can do':['Run health for operational readings and diagnostic readiness together.']}))
    from .system_resource_views import decisions
    resource_rows=decisions(data);rows.extend(resource_rows)
    resource_review=any(row.assessment in {'Critical','Review'} for row in resource_rows)
    resource_gap=any(row.assessment in {'Gap','Partial'} for row in resource_rows)
    source=data.get('failed_services')
    service_review=False
    if source is not None:
        available=source['state']=='available';count=len(source['rows']);service_review=available and count>0
        rows.append(Decision('Failed services',str(count)+(' failed service' if count==1 else ' failed services') if available else 'Could not be assessed',
            'Review' if service_review else 'Measured' if available else 'Gap',
            'Inspect the listed units and their logs; failure state alone does not establish impact or cause.' if service_review else
            'No failed service rows were returned; this does not prove that all applications work.' if available else
            'The bounded service query was unavailable or unsupported; no empty-success result is inferred.',source,
            {'What it means':'Observed system-manager service state only; not user units or proof of application impact.',
             'What you can do':(['In Health, open a listed service with Enter. CLI: faultlens service --unit NAME.service. Read status, logs, explanations and next steps; no service is restarted.'] if available else
                ['Optional source check with existing access: systemctl list-units --state=failed --type=service --all --plain --no-legend --no-pager --full']),
             'Evidence limits':source['limitations']},'failed_services'))
    readiness_start=len(rows)
    for key in ('journal.previous_boots','journal.service_active','journal.config.storage','atop.service_active','atop.recording_inventory'):
        item=by_key.get(key)
        if item is None: continue
        if key=='journal.config.storage' and item['value'] is None: continue
        row=observation(item)
        if key=='journal.previous_boots' and type(item['value']) is int and item['value']>0:
            row=Decision('Previous boots listed',str(item['value'])+(' boot' if item['value']==1 else ' boots'),row.assessment,row.meaning,item,row.detail)
        elif key=='journal.previous_boots' and item['value']==0:
            row=Decision('Previous boot visibility','No previous boots listed','Gap',
                'Earlier boot evidence is not visible here. Retention, access and incomplete history remain possible; no cause is inferred.',item,row.detail)
        elif key=='atop.recording_inventory' and isinstance(item['value'],dict):
            inventory=item['value'];value=str(inventory['files'])+' date-named files'
            row=Decision('Atop recordings',value,row.assessment,
                'Newest filename: '+str(inventory.get('newest_date') or 'not verified')+'. Replay the incident date to verify usable measurements and intervals.',item,row.detail)
            if inventory['files']==0:
                row=Decision(row.label,row.value,'Gap',row.meaning,item,row.detail)
        elif key in {'journal.service_active','atop.service_active'} and item['value'] in {'inactive','failed'}:
            row=Decision(row.label,row.value,'Gap',
                'Recorder service is not active. Existing history may still exist; this limits diagnostic readiness, not proof of a server fault.',item,row.detail)
        rows.append(row)
    for key in ('journal.storage.available','atop.storage.available'):
        item=by_key.get(key)
        if item is not None and item['value']==0:
            detail=observation_view(item)
            meaning='No unreserved log-filesystem space was observed. Review retention, reserved space and writer access before any deletion; recording failure is not established.'
            rows.append(Decision('Journal log space' if key.startswith('journal.') else 'Atop log space',
                '0 B unreserved','Review',meaning,item,{**detail,'What it means':meaning,
                'View threshold':'Readiness review hint: observed unreserved log-filesystem space ==0 bytes.'}))
    settings=[item for item in observations if item['key'].startswith(('journal.config.','atop.config.'))]
    if settings:
        unknown=sum(item['value'] is None for item in settings)
        rows.append(group('Recording configuration',settings,
            'Unspecified values may use defaults. Open details to distinguish explicit, unsupported and unavailable settings.',
            value=str(unknown)+' unknown; '+str(len(settings))+' checked',
            assessment='Review' if any(item['state']=='warning' for item in settings) else 'Info'))
    tools=[item for item in observations if item['key'].startswith('dependency.')]
    if tools:
        rows.append(group('Tools / feature support',tools,
            'Missing tools affect specific features; availability alone does not establish usability. No blanket installation is needed.',
            value=str(sum(item['value'] is True for item in tools))+'/'+str(len(tools))+' tools found'))
    gaps=sum(row.assessment=='Gap' for row in rows[readiness_start:])
    operational_gap=bool(missing) or resource_gap or (source is not None and source['state']!='available')
    summary=('Operational readings or failed service units need review.' if reviews or service_review or resource_review else
             'Operational evidence is incomplete; inspect available readings and source gaps.' if operational_gap else
             'No operational review flag was raised in the sampled checks.' if operational else
             'This report checks diagnostic readiness, not current operational health.')
    if gaps: summary+=' Some incident-data sources are unavailable.'
    if any(row.assessment in {'Review','Critical'} for row in rows[readiness_start:]):
        summary+=' Recording/readiness settings also need review.'
    step=('Inspect operational review rows first, then readiness gaps relevant to the incident.' if reviews or service_review or resource_review else
          'Inspect unverified operational sources before judging service/resource health; other readings may still be useful.' if operational_gap else
          'Review missing history/recording sources if you need incident reconstruction; unverified defaults alone call for no change.')
    return summary,step,rows+[_all(data)]


def interface(row,timing):
    detail=interface_view(row,timing)
    if row['state']!='compared' or row['delta'] is None or row['per_second'] is None:
        return Decision(row['interface'],'Not comparable','Gap',detail['What it means'],row,detail,'interface')
    error=sum(row['delta'][key] for key in ('receive_errors','receive_drops','send_errors','send_drops'))
    active=any(row['delta'][key]>0 for key in ('received_bytes','sent_bytes','received_packets','sent_packets'))
    assessment='Review' if error else 'Active' if active else 'Idle'
    meaning=('Combined error/drop counter delta '+str(error)+' (overlap possible); inspect individual counters and service symptoms.' if error else
             'Traffic was measured on this interface; no overload, route role or physical/virtual identity is inferred.' if active else
             'No traffic growth in this short comparison; inactivity outside the sample is unknown.')
    rates=row['per_second']
    from .presentation import size
    short=lambda value: size(value).replace('.0 ',' ').replace(' ','')+'/s'
    value='RX'+short(rates['received_bytes'])+' TX'+short(rates['sent_bytes'])
    return Decision(row['interface'],value,assessment,meaning,row,{**detail,'What it means':meaning},'interface')


def _network(data):
    timing=data.get('sample',{});observations=data.get('observations',[])
    source=next((item for item in observations if item['key']=='network.interfaces'),None)
    interfaces=source['value'] if source and isinstance(source['value'],list) else []
    classified=[interface(item,timing) for item in interfaces]
    rank={'Review':0,'Gap':1,'Active':2,'Idle':3}
    selected=sorted(classified,key=lambda row:rank[row.assessment])
    active=sum(row.assessment=='Active' for row in classified)
    review=sum(row.assessment=='Review' for row in classified)
    gaps=sum(row.assessment=='Gap' for row in classified)
    rows=[]
    if interfaces:
        rows.append(Decision('Interface summary',str(len(interfaces))+' interfaces',
            'Review' if review else 'Partial' if gaps else 'Measured',
            str(active)+' active without error/drop growth; '+str(review)+' to review; '+str(gaps)+' not comparable. All interfaces remain inspectable.',interfaces,
            {'What it means':'Activity and error/drop comparisons in the current namespace; never sum overlapping interface layers.'},'detail'))
        rows.extend(row for row in selected[:3] if row.assessment!='Idle')
    elif source is not None: rows.append(observation(source))
    else: rows.append(Decision('Interface comparisons','Not available','Gap','No interface comparison was collected.',None,{'What it means':'No traffic rates or interface-health conclusion can be inferred.'}))
    pressure=[item for item in observations if item['key'] in {finding['rule_id'] for finding in data.get('findings',[])}]
    protocol=[item for item in observations if item['key'].startswith(('network.tcp.','network.udp.')) or item['key'] in {'network.tcp','network.udp'}]
    unavailable=sum(item['state']=='unavailable' for item in protocol)
    rows.append(group('Protocol pressure',protocol,
        'Supported growth may reflect legitimate bursts, slow listeners or buffer limits; it does not establish a flood or cause.',
        value=str(len(pressure))+' increases; '+str(unavailable)+' unknown',
        assessment='Review' if pressure else 'Gap' if unavailable or not protocol else 'Measured'))
    sockets=data.get('sockets')
    if sockets is not None:
        available=sockets['state']=='available'
        rows.append(Decision('Socket snapshot',
            str(sockets.get('tcp_listener_rows',0))+' TCP listener rows; '+str(len(sockets['rows']))+' retained rows' if available else 'Could not be assessed',
            'Measured' if available else 'Gap','Local bindings do not prove Internet access. Open the snapshot to investigate relevant ports/services.',sockets,
            {'What it means':'Current local TCP/UDP snapshot; no owner attribution or external-reachability probe.'},'sockets'))
    else: rows.append(Decision('Socket snapshot','Not requested','Info','Enable socket endpoints only if needed to investigate service reachability.',None,{'What it means':'No socket evidence was requested.'}))
    if interfaces: rows.append(Decision('All interfaces',str(len(interfaces))+' retained interfaces','Info','Open the paged table for every interface, including idle and comparison gaps.',interfaces,{},'interfaces'))
    rows.append(_all(data))
    summary=('Sampled interface or protocol error/pressure counters need review.' if review or pressure else
             'Network evidence is incomplete; inspect the available comparisons and source gaps.' if gaps or not interfaces or unavailable or (sockets is not None and sockets['state']!='available') else
             'No supported error/drop or protocol-pressure growth was observed in this short sample.')
    elapsed=timing.get('elapsed_seconds')
    step=('Inspect highlighted error/pressure counters and service symptoms; compare legitimate workload before changes.' if review or pressure else
          'Inspect the source/comparison gaps needed for your investigation; missing data is not zero activity.' if gaps or not interfaces or unavailable or (sockets is not None and sockets['state']!='available') else
          'No change follows from this sample alone. Repeat during a network symptom; inspect sockets if a service cannot be reached.')
    scope='Current network namespace; interval '+(duration(elapsed) if elapsed is not None else 'not verified')+'. No interface-layer totals or route/role claims.'
    return summary,step,rows,scope


def build(data,kind=None):
    kind=kind or data['command']
    if kind=='network': summary,step,rows,scope=_network(data)
    else:
        summary,step,rows=_health(data) if kind in {'health','check'} else _system(data)
        scope=('Current PID/mount namespaces and caller access; bounded process and local-filesystem samples.'
               if 'processes' in data or 'filesystems' in data else 'Current visible sources; root filesystem only.')
        scope+=' Recorder readiness is separate from operational health.'
    detail={'Summary':summary,'What you can do':[step],'Scope':scope,
            'Important limits':['A short current snapshot does not establish an earlier cause or sustained conditions. No host configuration is changed.']}
    return {'summary':summary,'next_step':step,'scope':scope,'rows':rows,'detail':detail}
