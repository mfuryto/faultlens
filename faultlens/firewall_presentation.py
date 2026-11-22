"""Explain firewall expressions and Fail2ban reports without a guessed verdict."""
import json
from .investigation import utc


def view(data):
    snapshots=[source['data'] for key,source in data['sources'].items() if key in {'nftables','iptables4','iptables6'} and source['state']=='available']
    rule_count=sum(len(source['rules']) for source in snapshots)
    blocking=sum(bool(set(row['verdicts'])&{'drop','reject'}) for source in snapshots for row in source['rules'])
    defaults=sum(str(row['policy']).lower()=='drop' for source in snapshots for row in source['chains'])
    banned=sum(jail['currently_banned'] for jail in data['jails'])
    listing=data['sources']['fail2ban']
    ban_count=('Fail2ban reports no active jails; other blocking is not excluded.' if listing['state']=='available' and not listing['data']['jails'] else
        'Reported current-ban counter total '+str(banned)+' across '+str(len(data['jails']))+' examined jails; not unique addresses or independent verification.' if data['jails'] else
        'Current Fail2ban ban count could not be assessed.')
    rule_summary=(str(rule_count)+' retained rule expressions, including '+str(blocking)+' conditional drop/reject rules and '+str(defaults)+' default-drop policies.' if snapshots else
        'Kernel rule policy could not be assessed.')
    window=data['requested_window']
    return {'Answer':'No firewall or Fail2ban evidence could be assessed.' if data['state']=='unavailable' else
        rule_summary+' '+ban_count,
        'Current versus history':'Rules and jail status describe collection time '+data['collected_at']+'. They do not establish policy at an earlier incident.',
        'Journal scope':data['window']+' | UTC '+utc(window['since_realtime_us'])+' to '+utc(window['until_realtime_us'])+
            ' | optional boot '+str(data['boot_filter'] or 'none')+' | '+data['journal_scope']['requested'],
        'File scope':'Fixed current/previous file tails are separate, unfiltered context. Their local timestamps have no verified timezone or boot association.',
        'What it means':'Open a rule or default policy to see actual conditions, chain/hook/priority and counters. A ban report and matching address in a blocking expression are separate observations; final packet handling remains unverified.',
        'Who initiated it':'Fail2ban can report a jail action. Automatic versus manual initiation and the human administrator remain Unknown. Names/comments alone do not prove rule ownership.',
        'Action errors':str(sum(bool(record['observation'] and record['observation']['action'].startswith('Action error')) for record in data['records']))+' retained error reports; copied reports are not distinct incidents or proof of current enforcement failure.',
        'Preview limits':('Some jails were omitted. ' if data['jail_limit_reached'] else '')+('Some ban correspondences were omitted. ' if data['ban_preview_limit_reached'] else '')+'Inspect per-source availability, interpretation gaps and original fields.',
        'What you can do':['Open Rules and Chains, then Fail2ban jails and Reported bans. Follow a reported address to corresponding expressions and retained log messages.',
            'Check supported paths, direction, conditions and existing service evidence before changing a rule. Missing evidence does not establish that a ban is ineffective or a port is reachable.'],
        'Evidence limits':data['limitations']}


def source_detail(key,source):
    state=source['command_state']
    meaning='This source was read and its accepted evidence is retained.' if source['state']=='available' else {
        'missing':'No trusted optional executable was found.',
        'timeout':'The command exceeded its per-read deadline.',
        'time_limit':'The overall collection budget was reached before this source was read.',
        'output_limit':'The output exceeded the capture bound.',
        'boot_unavailable':'The current boot could not be resolved; no wider history query was substituted.',
        'file_missing':'The fixed optional log file was not found. The configured log target or rotation may differ.',
        'file_access_denied':'The operating system denied the file read under existing access.',
        'unsafe_file':'The path/file did not meet the no-symlink, ownership, permission or single-link checks; nothing was read.',
        'unsupported_encoding':'The bounded tail was not valid UTF-8; no guessed text was retained.',
    }.get(state,'The command did not provide usable evidence. This alone does not establish permission denial or absent rules/bans.')
    if source['reason']=='unsupported_or_over_limit_output':meaning='The command succeeded, but its format or amount was not accepted. No partial successful prefix or zero count was substituted.'
    backend=''
    original=(source.get('data') or {}).get('original','')
    if key.endswith('_backend') and isinstance(original,str):
        backend='nf_tables compatibility view; overlaps native nftables evidence' if '(nf_tables)' in original else 'legacy backend reported' if '(legacy)' in original else 'backend not established'
    content=source.get('data') or {}
    gaps=[]
    if content.get('record_limit_reached'):gaps.append('Only a bounded log tail is retained.')
    if content.get('unsupported_objects'):gaps.append('Some objects are retained without interpretation.')
    if content.get('count_list_consistent') is False:gaps.append('Reported current-ban count and address list disagree.')
    if any(row.get('unsupported') for row in content.get('rules',[])):gaps.append('Some rule expressions are not interpreted.')
    if content.get('changed_during_read'):gaps.append('The file changed during the read.')
    if backend:meaning+=' '+backend+'.'
    if key=='ufw' and isinstance(original,str):
        first=next((line for line in original.splitlines() if line.startswith('Status: ')),None)
        if first:meaning+=' UFW reports '+first.removeprefix('Status: ')+'. This frontend report does not replace kernel-rule inspection.'
    if key=='fail2ban' and 'jails' in content:meaning+=' Fail2ban reports '+str(len(content['jails']))+' active jails.'
    return {'Source':key,'What it means':meaning,'Backend':backend,'Command state':state,'Exit status':source['returncode'],
        'Reader reason':source['reason'],'Interpretation / history gaps':gaps or ['No additional gap established; source completeness remains unverified.'],
        'What you can do':['Inspect the original source and existing access/tool availability. Do not change policy or grant access merely to clear this status.']}


def conditions(rule):
    values=[]
    fields={'saddr':'source address','daddr':'destination address','sport':'source port','dport':'destination port'}
    protocols={'ip':'IPv4','ip6':'IPv6','tcp':'TCP','udp':'UDP'}
    flags={'-s':'source','--source':'source','-d':'destination','--destination':'destination','-p':'protocol','--protocol':'protocol',
        '--dport':'destination port','--dports':'destination ports','--sport':'source port','--sports':'source ports',
        '-i':'incoming interface','-o':'outgoing interface','--ctstate':'connection state','--state':'connection state',
        '-m':'match module','--comment':'reported comment','--reject-with':'reject response','--match-set':'ipset reference'}
    for value in rule['matches']:
        if isinstance(value,str):
            negated=value.startswith('! ');key,_,right=value.removeprefix('! ').partition(' ')
            values.append(('Not ' if negated else '')+flags.get(key,key)+' '+right);continue
        left=value.get('left',{});right=value.get('right');op=value.get('op','unsupported operator')
        name='Unresolved match expression'
        if isinstance(left,dict):
            if isinstance(left.get('payload'),dict):
                part=left['payload'];name=protocols.get(part.get('protocol'),str(part.get('protocol')))+' '+fields.get(part.get('field'),str(part.get('field')))
            elif isinstance(left.get('meta'),dict):name='Packet metadata '+str(left['meta'].get('key'))
            elif isinstance(left.get('ct'),dict):name='Connection tracking '+str(left['ct'].get('key'))
        if isinstance(right,str) and right.startswith('@'):
            values.append(name+(' is in set ' if op=='==' else ' '+str(op)+' set ')+right[1:])
        else:values.append(name+' '+{'==':'equals','!=':'differs from'}.get(op,str(op))+' '+json.dumps(right,ensure_ascii=True))
    return values or (['No supported match condition was decoded; inspect the complete original expression.'] if rule['unsupported'] else
        ['No explicit match predicate is listed in this rule; its action still requires the rule to be reached.'])


def rule_detail(rule,source,snapshot):
    parents=[chain for chain in snapshot['chains'] if (chain['family'],chain['table'],chain['name'])==(rule['family'],rule['table'],rule['chain'])]
    actions=' / '.join(rule['verdicts']) or 'continue or an unresolved extension'
    return {'What it means':'Reported action '+actions+' applies only if this chain is reached and its conditions match. A final packet path or effective block is not established.',
        'Rule scope':rule['family']+' / '+rule['table']+' / '+rule['chain']+' / handle or line '+str(rule['handle']),
        'Conditions':conditions(rule),'Reported verdicts':rule['verdicts'] or ['No supported terminating verdict'],
        'Chain / hook / priority / policy':parents or ['Parent chain unavailable'],
        'Jumps / goto':rule['links'],'Referenced address sets':rule['set_refs'],'Counters':rule['counters'] or ['Not recorded'],
        'Counter meaning':'Packets/bytes since an unverified reset, not distinct clients. Accept/log is not a verified final verdict.',
        'Interpretation gaps':rule['unsupported'] or ['Other rules, chain order, forwarding/NAT and external policy still require review.'],
        'Origin':'Unknown; labels and comments are retained assertions, not verified ownership.','Source':source,
        'What you can do':['Inspect the parent chain, incoming jumps, hook and priority, and compare the original rule with the affected traffic/service. No rule is changed.']}


def table(kind,data,options=None):
    from .workspace import Entry
    options=options or {};rows=[]
    if kind=='firewall_report':
        return 'Firewall / Fail2ban retained evidence',('Source / evidence','Meaning','State','Next step'),[
            Entry((label,'Current snapshot / retained logs',data['state'],'Enter opens evidence'),data,view(data),'firewall_'+key)
            for key,label in (('rules','Rules'),('chains','Chains / defaults'),('sets','Address sets'),('jails','Fail2ban jails'),('bans','Reported bans'),('sources','Source coverage'))]
    if kind=='firewall_sources':
        return 'Independent source coverage',('Source','State','Command / reader','Meaning'),[
            Entry((key,source['state'],source['command_state']+' / '+str(source['reason']),source_detail(key,source)['What it means']),source,
                source_detail(key,source),'detail') for key,source in data['sources'].items()]
    if kind=='firewall_jails':
        for jail in data['jails']:
            values={key:source['data']['value'] if source['state']=='available' else None for key,source in jail['settings'].items()}
            trigger=('Current maxretry '+str(values['maxretry'])+' matching failures within findtime '+str(values['findtime'])+' seconds; configured bantime '+str(values['bantime'])+' seconds (-1 means indefinite). Historical trigger/settings and actual remaining time are unverified.'
                if all(values.get(key) is not None for key in ('maxretry','findtime','bantime')) else 'A complete supported current threshold was not established; inspect individual sources.')
            detail={'What it means':'Current Fail2ban status; counters are daemon/jail lifetime values, not counts since boot. A reported ban does not prove action success.',
                'Current trigger settings':trigger,
                'Reported counters':{k:jail[k] for k in ('currently_failed','total_failed','currently_banned','total_banned')},
                'Current settings / actions':{k:source_detail('jail setting',v)|{'Original':v['data']} for k,v in jail['settings'].items()},
                'List/count consistent':jail['count_list_consistent'],'Human initiator':'Unknown',
                'What you can do':['Open reported bans and related retained logs. Current settings are not verified historical settings.']}
            rows.append(Entry((jail['jail'],str(jail['currently_banned'])+' reported bans',str(jail['currently_failed'])+' current failed matches','Enter opens current settings / logs'),jail,detail,'firewall_jail',navigation={'jail':jail['jail']}))
    elif kind=='firewall_bans':
        for item in data['correspondences']:
            if options.get('jail') and item['jail']!=options['jail']:continue
            rows.append(Entry((item['address'],item['jail'],item['assessment'],'Enter opens matches / related logs'),item,
                {'Reported address':item['address'],'Reported jail':item['jail'],'What it means':item['assessment']+'. '+item['enforcement'],
                 'Matching-rule preview':'Eight-reference cap reached; other expressions may exist.' if item['match_preview_limit_reached'] else 'Up to eight corresponding expression references; other policy constructs remain unresolved.',
                 'Who initiated it':item['initiator_reported']+'; human Unknown; ownership of corresponding rules unverified.',
                 'What you can do':['Inspect corresponding rules/sets and the log records. A missing supported match can reflect missing access, unsupported expressions, other backends or an action problem.'],
                 'Evidence limits':data['limitations']},'firewall_ban',navigation={'jail':item['jail'],'address':item['address'],'rule_refs':item['matches']}))
    elif kind in {'firewall_rules','firewall_chains','firewall_sets'}:
        for key in ('nftables','iptables4','iptables6'):
            source=data['sources'][key]
            if source['state']!='available':continue
            snapshot=source['data'];member=kind.removeprefix('firewall_')
            for index,item in enumerate(snapshot[member]):
                if member=='rules':
                    refs=options.get('rule_refs')
                    if refs is not None and not any(ref['source']==key and ref['rule_index']==index for ref in refs):continue
                    rows.append(Entry((key+' / '+item['family']+'/'+item['table']+'/'+item['chain'],' / '.join(item['verdicts']) or 'Continue / extension',str(item['handle']),'; '.join(conditions(item))),item,
                        rule_detail(item,key,snapshot),'detail'))
                elif member=='chains':
                    refs=[{'source':key,'rule_index':i} for i,row in enumerate(snapshot['rules']) if (row['family'],row['table'],row['chain'])==(item['family'],item['table'],item['name'])]
                    incoming=[row['original'] for row in snapshot['rules'] if any(link['target']==item['name'] for link in row['links']) and row['family']==item['family'] and row['table']==item['table']]
                    rows.append(Entry((key+' / '+item['name'],str(item['policy'] or 'No base policy'),str(item['hook'] or 'Regular chain'),'Enter opens policy / incoming links'),item,
                        {'What it means':'A base policy is conditional on the hook/chain path. Chain names alone do not establish creator or effective packet handling.',
                         'Reported chain':item,'Incoming links':incoming,'What you can do':['Open retained chain rules and review their order and conditions.']},'firewall_chain',navigation={'rule_refs':refs}))
                else:rows.append(Entry((key+' / '+item['name'],str(len(item['networks']))+' address entries',str(item['unsupported_elements'])+' unsupported entries','Enter opens full set'),item,
                    {'What it means':'Set membership alone does not block traffic. Inspect referencing rules and original element expiry/timeout metadata.','Reported set':item}))
    return kind.removeprefix('firewall_').title()+' — bounded evidence, final verdict Unknown',('Reported subject','Value / policy','Scope / state','Meaning / next step'),rows


def render(data,out,*,details=False,evidence=False):
    from .presentation import line
    print('Faultlens - Firewall and Fail2ban (read-only)',file=out)
    for key,value in view(data).items():
        if key=='Evidence limits' and not details:continue
        for text in value if isinstance(value,list) else [value]:line(out,key+': '+text)
    for key in ('nftables','iptables4','iptables6'):
        source=data['sources'][key]
        if source['state']!='available':continue
        for chain in source['data']['chains']:line(out,key+' | chain '+chain['name']+' | hook '+str(chain.get('hook'))+' | priority '+str(chain.get('priority'))+' | policy '+str(chain['policy']))
        for rule in source['data']['rules']:line(out,key+' | '+rule['chain']+' | '+str(rule['verdicts'])+' | '+json.dumps(rule['matches'],ensure_ascii=True))
    for jail in data['jails']:
        line(out,'Fail2ban jail '+jail['jail']+': '+str(jail['currently_banned'])+' reported current bans; human initiator Unknown.')
        for key,value in jail['settings'].items():line(out,'  '+key+': '+str(value['data']['original'] if value['data'] else 'Unavailable'))
    for value in data['correspondences']:line(out,value['address']+' | '+value['jail']+' | '+value['assessment']+'; enforcement/ownership unverified.')
    for key,source in data['sources'].items():line(out,'Coverage '+key+': '+source['state']+'; '+source_detail(key,source)['What it means'])
    for record in data['records']:
        if record['observation'] or evidence:line(out,'Recorded '+str(record.get('reported_local_time') or utc(record['reference']['realtime_us']))+' | '+str(record['message']))
    if details:line(out,'Technical sources: '+json.dumps(data['sources'],ensure_ascii=True))
