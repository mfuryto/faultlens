"""Explain bindings, conditional policy and the separate external-test requirement."""
import json
from .firewall_presentation import source_detail,rule_detail
from .presentation import line


def view(data):
    listeners=[data['sources'][key] for key in ('listeners4','listeners6')]
    readable=sum(s['state']=='available' for s in listeners)
    count=sum(len((s['data'] or {}).get('rows',[])) for s in listeners)
    answer=('Listening sockets could not be assessed; no absence of services can be established.' if not readable else
        str(count)+' listener/bound-UDP rows reported across '+str(readable)+' readable address families. '+
        ('One listener family was unavailable. ' if readable<2 else '')+
        'External accessibility has not been tested.')
    gaps=[key+': '+source_detail(key,s)['What it means'] for key,s in data['sources'].items() if s['state']!='available']
    if data.get('processes',{}).get('state') in {'partial','unavailable'}:gaps.append('Current process/cgroup associations are incomplete or unavailable; reported ss owner names/PIDs remain separate observations.')
    return {'Answer':answer,'Current evidence':data['collected_at']+' | current namespace | sequential reads',
        'How to investigate':'Open a port for its binding, reported owner/service and candidate addresses. Then open Policy for conditional rules/defaults and Routes for reported return-path configuration.',
        'Firewall INPUT':'The port list assesses new-flow INPUT rules in collected backends: Allowed, Blocked, Source dependent or Unresolved. Open a row for the source, target/interface, rule/default references and exact limits. This is separate from an external test.',
        'Forwarding':str(len(data['translations']))+' DNAT/redirect declarations in the preview. These can publish a port without a host listener; they do not prove a working container/service or external path.',
        'External verification':'Not performed. Local listening, a global address, a default route or an accept rule cannot certify Internet accessibility. Open External check for protocol-specific manual verification guidance.',
        'Coverage gaps':gaps or ['No command-source failure reported. Completeness, rule interpretation and external policy remain unverified.'],
        'Preview limits':('More listeners remain in original sources. ' if data['port_preview_capped'] else '')+
            ('More translations remain in original rules. ' if data['translation_preview_capped'] else '')+'At most 128 port/translation previews, 32 policy references and 32 addresses per binding; reference order is relevance, not packet evaluation order.',
        'What you can do':['Review expected services and each port binding before changing anything. Use the original rows to distinguish host listeners, proxies and translation declarations.',
            'Check separately authorized external paths from an independent network. Record source/target, IP family, protocol, UTC time and actual result; source-specific success is not a global exposure verdict.'],
        'Evidence limits':data['limitations']}


def external_check(row=None):
    tcp=row is not None and row.get('protocol')=='tcp';udp=row is not None and row.get('protocol')=='udp'
    return {'State':'Not performed; no external observation has been collected.',
        'Selected binding':('IPv'+str(row['family'])+' '+row['protocol'].upper()+' '+row['local']['original']) if row else 'Choose one port, family and intended external target.',
        'Target selection':'Use the independently confirmed public address and published port. Private, wildcard, loopback, link-local or special-use addresses are not Internet test targets. Upstream NAT may use a different public endpoint.',
        'Where to test':'An independent, separately authorized external network. A connection from this server, its LAN or a proxy can test a different path.',
        'TCP check':'Attempt one authorized TCP connection to the selected numeric target/port, then verify the expected application separately.' if tcp or not udp else 'Not applicable to this UDP binding.',
        'UDP check':'Use a valid, safe, service-specific request and a matching application response. A UDP send succeeding or silence does not prove open/closed.' if udp or not tcp else 'Not applicable to this TCP listener.',
        'Record':['Tester/source address and network, numeric target and port, IPv4 or IPv6, TCP or UDP, UTC timestamp, actual response/result and relevant source restrictions.',
            'A successful observation confirms that path at that time. Refusal/timeout can have several causes and do not prove a global firewall verdict.'],
        'Automatic actions':'None. Faultlens does not initiate a connection, DNS lookup, scan or upload, and does not invent a result.'}


def published(row):
    protocol=', '.join(('except ' if negated else '')+value.upper() for value,negated in row['protocol_predicates']) or 'protocol unresolved'
    ports=[]
    for ranges,negated in row['published_port_predicates']:
        value=', '.join(str(a) if a==b else str(a)+'-'+str(b) for a,b in ranges) if ranges is not None else 'unresolved destination port'
        ports.append(('except ' if negated else '')+value)
    return protocol+' '+(' and '.join(ports) if ports else 'any/unresolved destination port')


def incoming(ref,data):
    snapshot=data['sources'][ref['source']]['data'];values=[]
    for i in ref.get('incoming_rule_indices',[]):
        rule=snapshot['rules'][i];detail=rule_detail(rule,ref['source'],snapshot)
        values.append({'source':ref['source'],'rule_index':i,'chain':rule['chain'],'conditions':detail['Conditions'],'original':rule['original']})
    return values


def port_detail(row,data):
    source=data['sources'][row['source']]
    policies=[ref for ref in data['policies'] if ref['family'] in {'inet','ip' if row['family']==4 else 'ip6','bridge','netdev'}]
    rules=[(ref,data['sources'][ref['source']]['data']['rules'][ref['rule_index']]) for ref in row['policy_references']]
    allowed=sum('accept' in rule['verdicts'] for _,rule in rules);blocked=sum(bool(set(rule['verdicts'])&{'drop','reject'}) for _,rule in rules)
    examples=[]
    for ref,rule in rules[:3]:
        parents=incoming(ref,data)
        examples.append(ref['source']+' / '+rule['chain']+' | '+(', '.join(rule['verdicts']) or 'continue / extension')+' | '+
            '; '.join(rule_detail(rule,ref['source'],data['sources'][ref['source']]['data'])['Conditions'])+
            (' | incoming jump example: '+'; '.join(parents[0]['conditions']) if parents else ''))
    assessments=[]
    for backend in row['firewall']['backends']:
        for flow in backend['flows']:
            assessments.append(backend['source']+' | destination '+str(flow.get('destination') or 'not resolved')+' | candidate ingress '+
                (', '.join(flow.get('candidate_ingress_interfaces') or []) or 'not resolved')+' | '+flow['state'].replace('_',' ')+': '+flow['reason'])
            for chain in flow.get('input_chains',[]):assessments.append('Base policy: '+backend['source']+' / '+chain['table']+' / '+chain['chain']+' = '+str(chain['policy']))
    return {'What it means':row['binding']['meaning'],
        'Observed binding':'IPv'+str(row['family'])+' '+row['protocol'].upper()+' '+row['local']['original'],
        'Binding category':row['binding']['kind'],'Candidate local addresses':row['binding']['addresses'] or ['No assigned-address association established; address collection may be unavailable or the binding may be nonlocal.'],
        'Address preview capped':row['binding']['address_preview_capped'],
        'Reported owner / current service':row['owners'] or ['No owner was reported by ss under existing access. Root access does not guarantee complete attribution. Port numbers alone do not identify the application.'],
        'IPv4 / IPv6':row['binding']['ipv4_via_ipv6'],
        'Conditional policy':str(len(row['policy_references']))+' candidate references; '+('preview capped; ' if row['policy_preview_capped'] else '')+'open Policy to inspect actual conditions, chain ancestry and defaults. The supported INPUT assessment is separate from a complete packet-path verdict.',
        'Firewall INPUT assessment':row['firewall']['summary'],
        'Assessment scope':row['firewall']['scope'],
        'Assessed targets and base policies':assessments or ['No usable policy source was collected.'],
        'Other policy coverage':row['firewall']['coverage'],
        'Reported policy actions':str(allowed)+' accept and '+str(blocked)+' drop/reject expressions in the candidate preview. Counts are not verdicts: the INPUT assessment considers supported conditions, order and chain control. Compatibility views may overlap.',
        'Rule examples':examples or ['No supported rule correspondence established. Missing rules or sources do not establish an unfiltered port.'],
        'Incoming default policies':policies or ['No supported incoming base policy was established.'],
        'External access':'Unknown; no external test was performed.',
        'Source time':source['started_at']+' to '+source['finished_at'],
        'What you can do':['Open Policy, Addresses and Routes for the retained local evidence; review source restrictions, ordering, IPv4/IPv6, NAT and return paths.',
            'Open External check for an independent authorized test. Do not change a service/firewall rule merely because exposure is unknown.']}


def table(kind,data,options=None):
    from .workspace import Entry
    options=options or {};rows=[]
    if kind=='ports_report':
        return 'Port accessibility evidence',('Evidence','Scope','Assessment','Next step'),[
            Entry((label,'Current local evidence','External access unverified','Enter opens'),data,view(data),'ports_'+key)
            for key,label in (('listeners','Ports / owners'),('translations','Forwarding / NAT'),('sources','Source coverage'))]
    if kind=='ports_listeners':
        for i,row in enumerate(data['ports']):
            if 'port_indices' in options and i not in options['port_indices']:continue
            owners=', '.join(sorted({owner.get('service') or owner['reported_name'] for owner in row['owners']})) or 'Owner not reported'
            rows.append(Entry(('IPv'+str(row['family'])+' '+row['protocol'].upper()+' '+row['local']['original'],owners,row['binding']['kind'],row['firewall']['summary']),
                row,port_detail(row,data),'port',navigation={'refs':row['policy_references'],'family':row['family']}))
        return 'Ports — collected firewall INPUT assessment',('Binding','Reported owner/service','Binding scope','Firewall INPUT'),rows
    if kind=='ports_translations':
        for row in data['translations']:
            rule=data['sources'][row['source']]['data']['rules'][row['rule_index']]
            detail={'What it means':row['meaning'],'Reported translation':row,'Original rule':rule,
                'Target socket association':str(len(row['target_socket_indices']))+' compatible target socket references within the retained preview; missing correspondence does not prove an absent container/service. Other namespaces are not queried.',
                'Published port conditions':rule_detail(rule,row['source'],data['sources'][row['source']]['data'])['Conditions'],
                'What you can do':['Inspect the translation rule and its incoming path; then examine forwarding rules and target service/namespace. A container name or working target is not inferred.',
                    'Verify the separately confirmed public endpoint from an authorized external network; the published port may differ from the target port.']}
            rows.append(Entry((row['kind'].upper(),published(row),(str(row['target_address']) if row['target_address'] else 'address unresolved')+':'+(str(row['target_port']) if row['target_port'] is not None else 'port unchanged/unresolved'),'Conditional declaration'),row,detail,'port_translation',
                navigation={'refs':row['policy_references'],'port_indices':row['target_socket_indices'],'family':4 if row['family']=='ip' else 6 if row['family']=='ip6' else None}))
        return 'Forwarding / translation declarations (not verified exposure)',('Action','Published port predicates','Reported target','Assessment'),rows
    if kind=='ports_policy':
        for ref in options.get('refs',[]):
            source=ref['source'];snapshot=data['sources'][source]['data'];rule=snapshot['rules'][ref['rule_index']]
            detail=rule_detail(rule,source,snapshot)|{'Port association':ref,'Direct incoming rule context':incoming(ref,data) or ['No supported direct incoming link was established.'],
                'Referenced set evidence':[s for s in snapshot['sets'] if (s['family'],s['table'])==(rule['family'],rule['table']) and s['name'] in rule['set_refs']],
                'Reference selection':'Compatible literal protocol/port or unresolved/all-port predicates only; source/destination/interface/state restrictions, incoming jumps and rule order still apply. Parent constraints are not evaluated as a whole path.'}
            rows.append(Entry((source+' / '+rule['chain'],str(rule['handle']),', '.join(rule['verdicts']) or 'continue / extension',', '.join(ref['hooks']) or 'Ancestry unresolved'),rule,detail))
        for ref in data['policies']:
            if options.get('family') and ref['family'] not in {'inet','ip' if options['family']==4 else 'ip6','bridge','netdev'}:continue
            chain=data['sources'][ref['source']]['data']['chains'][ref['chain_index']]
            rows.append(Entry((ref['source']+' / '+chain['name'],'Default',str(chain['policy']),chain['hook']),chain,
                {'What it means':'This default applies only if evaluation reaches the end of this base chain; other chains/hooks and paths still apply.','Reported chain':chain}))
        return 'Candidate policy references and base defaults',('Source / chain','Handle / type','Reported action','Hook context'),rows
    if kind=='ports_addresses':keys=('addresses',)
    elif kind=='ports_routes':keys=('routes4','routes6')
    elif kind=='ports_sources':keys=tuple(data['sources'])
    else:raise ValueError('Unsupported port view')
    for key in keys:
        source=data['sources'][key];detail=source_detail(key,source)
        if key.startswith('routes'):detail|={'What it means':'Reported route configuration only. Default routes and next hops do not verify policy routing, replies, connectivity or Internet access.','Original route rows':(source['data'] or {}).get('rows',[])}
        if key=='addresses':detail|={'Reported addresses / link flags':(source['data'] or {}).get('rows',[])}
        rows.append(Entry((key,source['state'],source['command_state']+'; exit '+str(source['returncode']),detail['What it means']),source,detail))
    return 'Independent port source evidence',('Source','State','Command','Meaning'),rows


def render(data,out,*,details=False,evidence=False):
    print('Faultlens - Port accessibility (read-only)',file=out)
    for key,value in view(data).items():
        if key=='Evidence limits' and not details:continue
        for text in value if isinstance(value,list) else [value]:line(out,key+': '+text)
    for entry in table('ports_listeners',data)[2]:
        row=entry.original;line(out,' | '.join(entry.cells));line(out,'  Meaning: '+entry.detail['What it means'])
        for assessment in entry.detail['Assessed targets and base policies'][:8]:line(out,'  INPUT: '+assessment)
        for address in row['binding']['addresses']:
            flags=list(address['address_flags'])+[key for key in ('tentative','dadfailed','deprecated') if address[key]]
            line(out,'  Address: '+address['address']+' on '+address['ifname']+' | '+str(address['operstate'])+' | '+address['kind']+(' | '+', '.join(flags) if flags else ''))
        if not row['binding']['addresses']:line(out,'  Address association not established; inspect original source coverage.')
        for owner in row['owners']:line(out,'  Reported owner: '+owner['reported_name']+' | PID '+str(owner['pid'])+' | FD '+str(owner['fd'])+' | service '+str(owner['service'] or 'unverified'))
        line(out,'  Policy: '+entry.detail['Reported policy actions'])
        for example in entry.detail['Rule examples']:line(out,'  Rule: '+example)
        if row['policy_preview_capped']:line(out,'  More policy references were omitted from this preview; inspect original rules.')
    for entry in table('ports_translations',data)[2]:
        line(out,' | '.join(entry.cells));line(out,'  Meaning: '+entry.detail['What it means'])
        for condition in entry.detail['Published port conditions']:line(out,'  Condition: '+condition)
    for key,value in external_check().items():
        if key in {'Where to test','TCP check','UDP check','Record'}:
            for text in value if isinstance(value,list) else [value]:line(out,key+': '+text)
    if details or evidence:line(out,'Retained original evidence: '+json.dumps(data,ensure_ascii=True))
    else:line(out,'Use --details or --json for complete accepted fields; Network -> Port accessibility opens policy, addresses, routes and reported services.')
