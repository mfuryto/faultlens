"""Shared evidence-backed network investigation cards; never an attack verdict."""
from collections import defaultdict

MAX_CARDS=32
LIMITS=[
    'A reported symptom or Possible pattern is not a verified attack, compromise, service outage or underlying cause.',
    'Legitimate demand, backups, administration, proxies/NAT/load balancers, retries and insufficient application capacity can resemble attack indicators.',
    'Current snapshots cannot reconstruct earlier traffic. A quiet sample cannot rule out earlier or intermittent activity.',
    'Host evidence cannot measure upstream saturation or reconstruct unrecorded packets/per-peer UDP traffic. Review existing edge/provider evidence when relevant.',
    'Source coverage and authenticity remain limited; missing access, resets, rotation, rate limits and collection caps never become an all-clear.',
]
PRESSURE={'SyncookiesSent':'SYN cookies were sent','ListenOverflows':'TCP listener overflow reports increased',
    'ListenDrops':'TCP listener drops increased','AttemptFails':'TCP connection attempts failed',
    'EstabResets':'Established TCP connections were reset','RetransSegs':'TCP segments were retransmitted',
    'InErrs':'TCP input errors increased','InErrors':'UDP input errors increased',
    'RcvbufErrors':'UDP receive buffer errors increased','SndbufErrors':'UDP send buffer errors increased',
    'Udp6InErrors':'IPv6 UDP input errors increased','Udp6RcvbufErrors':'IPv6 UDP receive buffer errors increased',
    'Udp6SndbufErrors':'IPv6 UDP send buffer errors increased'}


def card(identity,title,observed,meaning,evidence,*,assessment='Review',alternatives=None,next_steps=None,**metadata):
    return dict(id=identity,title=title,assessment=assessment,observation=observed,meaning=meaning,evidence=evidence,
        alternatives=alternatives or ['Legitimate bursts, loss/retries, slow applications, resource limits or local policy may explain this observation.'],
        next_steps=next_steps or ['Repeat during the symptom; inspect affected endpoints, reported services and existing logs for the selected period before making changes.'],
        attack_assessment='Unknown',root_cause='Unknown',**metadata)


def finish(data,values,coverage):
    retained=values[:MAX_CARDS]
    requested=[value for value in coverage.values() if value!='not_requested']
    data['network_review']={'state':'not_requested' if not requested else 'available' if all(value=='available' for value in requested) else
        'partial' if any(value in {'available','partial'} for value in requested) else 'unavailable',
        'cards':retained,'matching_cards':len(values),'card_limit':MAX_CARDS,'cards_truncated':len(values)>MAX_CARDS,
        'sources':coverage,'attack_assessment':'Unknown','root_cause':'Unknown','limitations':list(LIMITS)}


def live(data):
    samples=data.get('network_samples') or [{'sample_index':0,'sample':data['sample'],'observations':data['observations'],'state':data['state']}]
    values=[];groups=defaultdict(list)
    for sample in samples:
        elapsed=sample['sample'].get('elapsed_seconds')
        for item in sample['observations']:
            if item['state']=='unavailable' or item['value'] is None:continue
            field=item['key'].rsplit('.',1)[-1]
            if field in PRESSURE and isinstance(item['value'],dict) and item['value']['delta']>0:
                groups[item['key']].append({'sample_index':sample['sample_index'],'source':item['source'],
                    'counter':field,**item['value'],'interval_seconds':elapsed,
                    'per_second':round(item['value']['delta']/elapsed,2) if elapsed else None})
            if item['key']=='network.interfaces':
                for row in item['value']:
                    if row['state']=='compared' and any(row['delta'][key]>0 for key in ('receive_errors','send_errors','receive_drops','send_drops')):
                        groups['interface.'+row['interface']].append({'sample_index':sample['sample_index'],'interface':row['interface'],
                            'delta':row['delta'],'per_second':row['per_second'],'interval_seconds':elapsed})
    for key,refs in sorted(groups.items()):
        title=PRESSURE.get(key.rsplit('.',1)[-1], 'Interface errors or drops on '+key.removeprefix('interface.'))
        observed=(str(sum(ref['delta'] for ref in refs))+' additional counter events' if type(refs[0]['delta']) is int else 'Error/drop growth observed')
        values.append(card(key,title,observed+' in '+str(len(refs))+' of '+str(len(samples))+' measured intervals.',
            'Observed counter growth is concrete evidence of the reported condition; counters can overlap and do not establish its cause or a responsible peer/service.',refs))
    sockets=data.get('sockets',{});socket_values=sockets.get('rows',[])
    groups=defaultdict(list)
    for row in socket_values:
        if row['protocol']=='tcp':groups[(row['state'],row['local']['original'])].append(row)
        if row['protocol']=='tcp' and row['state']=='LISTEN' and row['send_queue']>0 and row['receive_queue']*100>=row['send_queue']*80:
            values.append(card('listener.queue.'+str(row['row_index']),'TCP accept queue is near its reported limit',
                row['local']['original']+': '+str(row['receive_queue'])+' queued / '+str(row['send_queue'])+' reported backlog.',
                'A single LISTEN snapshot reports queue occupancy, not bytes, a connection rate or sustained exhaustion.',
                [{'socket_row_index':row['row_index'],'receive_queue':row['receive_queue'],'send_queue':row['send_queue']}],
                services=sorted({owner['service'] for owner in row.get('owners',[]) if owner.get('service')}),socket_indices=[row['row_index']]))
    for (state,local),rows in sorted(groups.items()):
        if state not in {'SYN-RECV','SYN-SENT','CLOSE-WAIT'} or len(rows)<10:continue
        meaning={'SYN-RECV':'Pending TCP handshakes; short-lived demand, loss, backlog pressure or unsolicited requests are alternatives.',
            'SYN-SENT':'TCP connection attempts await responses; unavailable remote services, loss, policy or unexpected application activity are alternatives.',
            'CLOSE-WAIT':'The local application has not completed closing; inspect application behavior before claiming a leak or attack.'}[state]
        values.append(card('socket.'+state+'.'+local,'Repeated '+state+' rows at one local endpoint',
            local+': '+str(len(rows))+' retained TCP rows.',meaning,
            [{'socket_row_indices':[row['row_index'] for row in rows]}],socket_indices=[row['row_index'] for row in rows],
            services=sorted({owner['service'] for row in rows for owner in row.get('owners',[]) if owner.get('service')})))
    peers=defaultdict(list)
    for row in socket_values:
        if row['peer']['port'] is not None:peers[row['peer']['address']].append(row)
    for peer,rows in sorted(peers.items(),key=lambda item:(-len(item[1]),item[0]))[:8]:
        values.append(card('peer.'+peer,'Review whether this reported peer is expected',
            peer+': '+str(len(rows))+' retained socket rows; local endpoints '+', '.join(sorted({row['local']['original'] for row in rows})[:8])+'.',
            'An endpoint alone cannot classify a connection as malicious, outbound-initiated, authenticated or authorized. Port numbers do not identify an application.',
            [{'socket_row_indices':[row['row_index'] for row in rows]}],assessment='Info',
            alternatives=['Expected clients, monitoring, backups, proxies, NAT or a local application may explain these endpoints.'],
            next_steps=['Inspect the original socket rows and permitted owner/service association. Compare expected application configuration and retained service/authentication/firewall logs.'],
            socket_indices=[row['row_index'] for row in rows],reported_peer=peer))
    sources=data.get('network_context',{}).get('sources',{})
    for row in sources.get('addresses',{}).get('rows',[]):
        if 'UP' in row.get('flags',[]) and row.get('operstate')=='DOWN':
            values.append(card('link.down.'+str(row['ifindex']),'Enabled interface reports operational state DOWN',
                row['ifname']+': administrative UP; operational DOWN; flags '+', '.join(row.get('flags',[]))+'.',
                'The configured interface is enabled but reports DOWN in this snapshot. Relevance to the affected service or route remains unverified.',
                [{'source':'network_context.addresses','ifindex':row['ifindex'],'ifname':row['ifname'],'operstate':row['operstate'],'flags':row.get('flags',[])}],
                alternatives=['An unused/partially configured virtual interface, disconnected peer/link or temporary transition may explain this state.'],
                next_steps=['Check whether the affected address/route uses this interface, then inspect existing link, virtual-network and service logs. Do not change the interface from this snapshot alone.']))
        for address in row.get('addr_info',[]):
            if address.get('dadfailed') is True or 'dadfailed' in address.get('flags',[]):
                values.append(card('address.dad.'+str(row['ifindex'])+'.'+address['local'],'Address reports duplicate-address detection failure',
                    row['ifname']+' | '+address['local']+'/'+str(address['prefixlen']),
                    'The address source reports failed duplicate-address detection. An actual conflicting host or the underlying cause is not established.',
                    [{'source':'network_context.addresses','ifindex':row['ifindex'],'address':address}],
                    alternatives=['Address configuration conflicts, duplicated virtual-network identities or topology/packet behavior may explain this flag.'],
                    next_steps=['Inspect the address configuration and retained interface/kernel logs using existing access. No remote detection probe or address change is performed.']))
    for key in ('routes4','routes6'):
        special=[row for row in sources.get(key,{}).get('rows',[]) if row.get('type') in {'blackhole','unreachable','prohibit','throw'}]
        if special:
            values.append(card('route.special.'+key,'Route table contains explicit discard/reject/control entries',
                key+': '+str(len(special))+' retained control entries; first '+str(special[0].get('dst','default'))+' / '+special[0]['type']+'.',
                'These are configured entries, often intentional. Policy rules and table selection were not evaluated; no claim is made that a particular connection used them.',
                [{'source':'network_context.'+key,'entries':special}],assessment='Info',
                next_steps=['Compare the original destination, route type, table and next-hop context with the symptom and intended routing policy. No route is tested or changed.']))
    coverage={'counter_samples':data.get('counter_state',data['state']),'sockets':sockets.get('state','not_requested'),
              'authentication_firewall_history':'not_requested'}
    coverage.update({key:value['state'] for key,value in data.get('network_context',{}).get('sources',{}).items()})
    if data.get('network_context',{}).get('processes'):coverage['process_associations']=data['network_context']['processes']['state']
    if not data.get('network_context'):coverage['addresses_routes']='not_requested'
    finish(data,values,coverage)


def historical(data):
    analysis=data['security_analysis'];values=[]
    for index,finding in enumerate(analysis['findings']):
        refs=finding['evidence'];ref=refs[0];source=ref.get('source_analysis')
        indices=ref.get('candidate_indices',[]);records=data.get(source,{}).get('records',[]) if source else []
        retained=[records[position] for position in indices if type(position) is int and 0<=position<len(records)]
        times=[record['reference']['realtime_us'] for record in retained]
        observed=finding['observation']
        if ref.get('reported_source_addresses'):observed+=' Reported peers '+', '.join(ref['reported_source_addresses'])+'.'
        if ref.get('reported_source_address'):observed+=' Reported source '+ref['reported_source_address']+'.'
        if ref.get('reported_destination_address'):observed+=' Destination '+ref['reported_destination_address']+'.'
        if ref.get('report_count') is not None:observed+=' '+str(ref['report_count'])+' retained reports.'
        if ref.get('destination_ports'):observed+=' Destination ports '+', '.join(map(str,ref['destination_ports']))+'.'
        values.append(card(finding['rule_id']+'.'+str(index),finding['title'],observed,finding['reasoning'],refs,
            assessment='Possible',source_key=source,candidate_indices=indices,
            window={'since_us':min(times),'until_us':max(times),'boot_id':ref.get('boot_id')} if times else None,
            next_steps=['Open the original referenced records and reported peers/ports. Inspect existing service logs for the same period; logging labels and repeated reports do not establish an attack or successful misuse.'],
            alternatives=['Administration, scanners used by the owner, misconfiguration, NAT/proxies, duplicated logging or legitimate traffic bursts can match these heuristics.']))
    finish(data,values,analysis['sources'])
    review=data['network_review']
    review['historical_comparison']=analysis['historical_comparison']
    review['cards_truncated'] |= analysis['findings_truncated']
    review['matching_cards']=analysis['matching_indicators']
    review['coverage']={key:{'state':data.get(key,{}).get('state','not_requested'),
        'record_limit_reached':data.get(key,{}).get('record_limit_reached'),
        'unsupported_messages':data.get(key,{}).get('unsupported_messages_in_response')} for key in ('ssh_analysis','firewall_analysis','atop')}


def detail(value,review):
    return {'Observed':value['observation'],'What it means':value['meaning'],
        'Alternative explanations':value['alternatives'],'What you can do':value['next_steps'],
        'Assessment':value['assessment']+' observation; attack Unknown; root cause Unknown.',
        'Evidence references':value['evidence'],'Evidence limits':review['limitations']}


def decisions(data):
    from .current_views import Decision
    result=[];review=data.get('network_review')
    if review:
        count=sum(row['assessment'] in {'Review','Possible'} for row in review['cards'])
        meaning='Open concrete observations, alternatives and next investigations. Current sources do not inspect authentication/firewall history; use the log inquiry. No cards or a quiet snapshot is not an all-clear.'
        result.append(Decision('Network investigation',str(count)+' review observations; '+str(len(review['cards']))+' retained cards',
            'Review' if count else 'Gap' if review['state']=='unavailable' else 'Partial' if review['state']=='partial' else 'Info',
            meaning,review,{'What it means':meaning,'Source coverage':review['sources'],
                'Retained cards':str(len(review['cards']))+' of '+str(review['matching_cards'])+'; cap '+str(review['card_limit']),
                'Evidence limits':review['limitations']},'network_issues'))
        for row in review['cards'][:3]:
            if row['assessment'] in {'Review','Possible'}:
                result.append(Decision(row['title'],row['observation'],row['assessment'],row['meaning'],row,detail(row,review),'network_issue'))
    context=data.get('network_context')
    if context:
        sources=context['sources'];addresses=sources['addresses'];routes=[sources[key] for key in ('routes4','routes6')]
        source_states=[source['state'] for source in [addresses,*routes]]
        state='Measured' if all(value=='available' for value in source_states) else 'Partial' if any(value=='available' for value in source_states) else 'Gap'
        meaning='Open local addresses/link flags and separate IPv4/IPv6 route tables. Configuration does not prove usable connectivity or Internet exposure.'
        result.append(Decision('Addresses and routes',str(len(addresses['rows']))+' reported interfaces; '+str(sum(len(source['rows']) for source in routes))+' route rows',
            state,meaning,context,
            {'What it means':meaning,'What you can do':['Inspect interface flags, address family, route table/type and configured next hops. Policy rules, VRFs and external connectivity require separate context.'],
             'Evidence limits':context['limitations']},'network_context'))
    if data.get('network_samples'):
        samples=data['network_samples']
        result.append(Decision('Measured intervals',str(len(samples))+' independent short samples','Measured' if all(row['state']=='available' for row in samples) else 'Partial',
            'Compare actual per-interface byte/packet rates and protocol deltas across the retained intervals. Three short intervals are not a baseline or continuous coverage.',
            {'state':'retained','rows':samples}, {'What it means':'No host throughput is computed by summing interface layers. Burst peaks between samples remain unknown.'},'network_samples'))
    if data.get('network_context'):
        result.append(Decision('SSH authentication history','Choose a time window','Info',
            'Inspect failed/accepted authentication reports, reported usernames, peers and time buckets. Uses accessible logs, not current socket counts.',
            None,{},'ssh_statistics'))
        result.append(Decision('Firewall and Fail2ban','Inspect current policy / retained logs','Info',
            'Review conditional rules/defaults and reported bans with original evidence. No policy changes or reachability verdict.',None,{},'firewall_state'))
    return result


def render(data,out):
    from .presentation import line
    review=data.get('network_review')
    if not review:return
    print('\nNetwork investigation — attack and root cause remain Unknown',file=out)
    line(out,'Source coverage: '+', '.join(key+' '+value for key,value in review['sources'].items()))
    if not review['cards']:
        line(out,'No supported review pattern was established in the assessed sources. Missing sources and quiet samples cannot establish absence of an earlier or current attack.')
    for value in review['cards']:
        line(out,value['title']+' ['+value['assessment']+']','  ')
        line(out,value['observation'],'    ')
        line(out,value['meaning'],'    ')
        line(out,'Alternatives: '+value['alternatives'][0],'    ')
        line(out,'Next: '+value['next_steps'][0],'    ')
    if review['cards_truncated']:line(out,'The review-card cap was reached; complete retained source rows and references remain in details/JSON.')
    for limit in review['limitations']:line(out,'Limit: '+limit)
