"""Port-related policy references, never a packet-path or Internet verdict."""
import ipaddress
import re
import shlex


def port_values(value):
    """Literal numeric intervals only; dynamic maps and named sets stay unresolved."""
    if type(value) is int and 0<=value<=65535:return [(value,value)]
    if isinstance(value,dict) and set(value)=={'range'}:
        ends=value['range']
        if isinstance(ends,list) and len(ends)==2 and all(type(v) is int and 0<=v<=65535 for v in ends) and ends[0]<=ends[1]:return [tuple(ends)]
    if isinstance(value,dict) and set(value)=={'set'} and isinstance(value['set'],list) and len(value['set'])<=128:
        ranges=[port_values(v) for v in value['set']]
        if all(v is not None for v in ranges):return [pair for rangeset in ranges for pair in rangeset]
    if isinstance(value,str) and re.fullmatch(r'[0-9:,]{1,128}',value):
        ranges=[]
        for part in value.split(','):
            ends=part.split(':')
            if len(ends)>2 or any(not v for v in ends):return None
            a,b=int(ends[0]),int(ends[-1])
            if not 0<=a<=b<=65535:return None
            ranges.append((a,b))
        return ranges
    return None


def predicates(rule):
    protocols=[];ports=[];unresolved=False
    for item in rule['matches']:
        if isinstance(item,str):
            negated=item.startswith('! ');flag,_,value=item.removeprefix('! ').partition(' ')
            if flag in {'-p','--protocol'}:
                protocol={'6':'tcp','17':'udp'}.get(value,value)
                if protocol in {'tcp','udp'}:protocols.append((protocol,negated))
                else:unresolved=True
            if flag in {'--dport','--dports'}:ports.append((port_values(value),negated))
            continue
        left=item.get('left',{});op=item.get('op');right=item.get('right')
        if not isinstance(op,str):unresolved=True;continue
        if not isinstance(left,dict):unresolved=True;continue
        payload=left.get('payload',{});meta=left.get('meta',{})
        if isinstance(payload,dict) and payload.get('field')=='dport':
            protocol=payload.get('protocol')
            if protocol in {'tcp','udp'}:protocols.append((protocol,False))
            if op in {'==','!='}:ports.append((port_values(right),op=='!='))
            else:unresolved=True
        if isinstance(meta,dict) and meta.get('key')=='l4proto':
            protocol={6:'tcp',17:'udp'}.get(right,right) if isinstance(right,(str,int)) else None
            if protocol in {'tcp','udp'} and op in {'==','!='}:protocols.append((protocol,op=='!='))
            else:unresolved=True
    return protocols,ports,unresolved


def index(sources):
    entries=[];policies=[]
    for source_name in ('nftables','iptables4','iptables6'):
        source=sources[source_name]
        if source['state']!='available':continue
        data=source['data'];chains={(c['family'],c['table'],c['name']):c for c in data['chains']}
        incoming={key:set() for key in chains};incoming_rules={key:[] for key in chains}
        for rule_index,rule in enumerate(data['rules']):
            origin=(rule['family'],rule['table'],rule['chain'])
            for link in rule['links']:
                target=(rule['family'],rule['table'],link['target'])
                if target in incoming:
                    incoming[target].add(origin);incoming_rules[target].append(rule_index)
        def hooks(key):
            seen=set();todo=[key];found=set()
            while todo and len(seen)<64:
                current=todo.pop()
                if current in seen:continue
                seen.add(current);chain=chains.get(current,{})
                if chain.get('hook'):found.add(str(chain['hook']))
                todo.extend(incoming.get(current,set())-seen)
            return sorted(found),bool(todo)
        for position,chain in enumerate(data['chains']):
            if chain.get('hook') in {'input','forward','prerouting','ingress'}:
                policies.append({'source':source_name,'chain_index':position,'family':chain['family'],'hook':chain['hook'],'policy':chain['policy']})
        for position,rule in enumerate(data['rules']):
            selected,capped=hooks((rule['family'],rule['table'],rule['chain']))
            if selected and not set(selected)&{'input','forward','prerouting','ingress'}:continue
            protocols,ports,unresolved=predicates(rule)
            entries.append({'source':source_name,'rule_index':position,'family':rule['family'],'hooks':selected,
                'incoming_rule_indices':incoming_rules.get((rule['family'],rule['table'],rule['chain']),[])[:8],
                'incoming_preview_capped':len(incoming_rules.get((rule['family'],rule['table'],rule['chain']),[]))>8,
                'chain_walk_capped':capped,'protocols':protocols,'ports':ports,'unresolved':unresolved})
    entries.sort(key=lambda entry:(not bool(entry['ports']),'input' not in entry['hooks']))
    return entries,policies


def related(entry,family,protocol,port):
    if entry['family'] not in {'inet','ip' if family==4 else 'ip6','bridge','netdev'}:return False
    for value,negated in entry['protocols']:
        if (protocol==value)==negated:return False
    for ranges,negated in entry['ports']:
        if ranges is not None and (any(a<=port<=b for a,b in ranges)==negated):return False
    return True


def references(indexed,family,protocol,port):
    refs=[];count=0
    for entry in indexed:
        if not related(entry,family,protocol,port):continue
        count+=1
        if len(refs)<32:refs.append({'source':entry['source'],'rule_index':entry['rule_index'],'hooks':entry['hooks'],
            'incoming_rule_indices':entry['incoming_rule_indices'],'incoming_preview_capped':entry['incoming_preview_capped'],
            'association':'Literal destination-port predicate' if entry['ports'] and all(v is not None for v,_ in entry['ports']) else 'No resolved destination-port restriction',
            'path':'Candidate incoming chain ancestry only; predicates/order remain unresolved',
            'chain_walk_capped':entry['chain_walk_capped']})
    return refs,count>len(refs)


def translations(indexed,sources):
    """Retain DNAT/redirect declarations even without a host listening socket."""
    rows=[]
    for entry in indexed:
        rule=sources[entry['source']]['data']['rules'][entry['rule_index']];original=rule['original'];actions=[]
        if isinstance(original,dict):
            for item in original['expr']:
                for kind in ('dnat','redirect'):
                    if kind in item:actions.append((kind,item[kind]))
        else:
            tokens=shlex.split(original)
            targets=[tokens[i+1] for i,v in enumerate(tokens[:-1]) if v in {'-j','--jump'}]
            if any(v in {'DNAT','REDIRECT'} for v in targets):
                options={v:tokens[i+1] for i,v in enumerate(tokens[:-1]) if v in {'--to-destination','--to-ports'}}
                actions.append(('dnat' if 'DNAT' in targets else 'redirect',options))
        for kind,target in actions:
            address=None;port=None
            if isinstance(target,dict):
                if entry['source']=='nftables':
                    addr=target.get('addr');raw_port=target.get('port')
                    if type(raw_port) is int and 0<=raw_port<=65535:port=raw_port
                else:
                    value=target.get('--to-destination','');addr=value;raw_port=target.get('--to-ports')
                    match=re.fullmatch(r'(?:\[([^\]]+)\]|([0-9.]+)):([0-9]{1,5})',value)
                    if match:addr=match[1] or match[2];raw_port=match[3]
                    if isinstance(raw_port,str) and raw_port.isdecimal() and 0<=int(raw_port)<=65535:port=int(raw_port)
                if isinstance(addr,str):
                    try:address=str(ipaddress.ip_address(addr))
                    except ValueError:pass
            rows.append({'source':entry['source'],'rule_index':entry['rule_index'],'kind':kind,'target_address':address,'target_port':port,
                'target_original':target,'published_port_predicates':entry['ports'],'protocol_predicates':entry['protocols'],
                'hooks':entry['hooks'],'family':entry['family'],'external_access':'Unknown',
                'meaning':'Translation declaration only; predicates, chain reachability, forwarding, target namespace/service and return path remain unverified.'})
    return rows
