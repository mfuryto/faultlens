"""Bounded INPUT-chain assessment, separate from external or whole-path reachability."""
import ipaddress
import shlex
from .firewall_rules import network
from .port_rules import port_values

SCOPE='New tracked TCP SYN / new UDP flow in collected IP/inet INPUT chains; other hooks, NAT, routing and external paths are separate.'


def new_state(value):
    if isinstance(value,dict) and set(value)=={'set'}:
        value=value['set']
        if not isinstance(value,list):return None
    elif isinstance(value,list):return None
    values=value if isinstance(value,list) else [value]
    known={'invalid':1,'established':2,'related':4,'new':8,'untracked':64}
    if any(type(v) not in {str,int} for v in values):return None
    states=[known.get(v,int(v) if isinstance(v,str) and v.isdecimal() and len(v)<=3 else v) for v in values]
    if 8 in states:return True
    if any(type(v) is not int or v<0 or v&~79 or v&8 for v in states):return None
    return False


def protocol_test(value,actual,family=False):
    if isinstance(value,dict) and set(value)=={'set'}:
        values=value['set']
        if not isinstance(values,list):return None
    elif isinstance(value,list):return None
    else:values=[value]
    names={'ipv4':2,'ipv6':10,'arp':3,'bridge':7,'inet':1,'netdev':5,'unspec':0} if family else {
        'tcp':6,'udp':17,'icmp':1,'icmpv6':58,'ipv6-icmp':58,'igmp':2,'gre':47,'esp':50,'ah':51,'sctp':132,'dccp':33,'udplite':136}
    numbers=[]
    for v in values:
        if type(v) not in {str,int}:return None
        n=names.get(v,int(v) if isinstance(v,str) and v.isdecimal() and len(v)<=3 else v)
        if type(n) is not int or not 0<=n<=255:return None
        numbers.append(n)
    return actual in numbers


class InputPolicy:
    """Three-valued matches keep unresolved branches; no unknown becomes an allow."""
    def __init__(self,sources):
        self.sources=sources;self.cache={};self.remaining=32768;self.contexts=0;self.snapshots={}
        interfaces=((sources.get('addresses',{}).get('data') or {}).get('rows',[]))
        self.loopbacks=tuple(sorted({v['ifname'] for v in interfaces if 'LOOPBACK' in v.get('flags',[])}))
        self.ingress=tuple(sorted({v['ifname'] for v in interfaces if 'LOOPBACK' not in v.get('flags',[])}))
        self.interface_cache={}
        for name in ('nftables','iptables4','iptables6'):
            source=sources[name]
            if source['state']!='available':continue
            data=source['data'];chains={(c['family'],c['table'],c['name']):c for c in data['chains']};rules={key:[] for key in chains}
            for i,rule in enumerate(data['rules']):rules.setdefault((rule['family'],rule['table'],rule['chain']),[]).append((i,rule))
            self.snapshots[name]=(data,chains,rules)

    def one(self,name,flow):
        cache_key=(name,*flow)
        if cache_key in self.cache:return self.cache[cache_key]
        if self.contexts>=128 or self.remaining<=0:return {'state':'unresolved','reason':'Report evaluation budget reached','outcomes':['unknown'],'references':[]}
        self.contexts+=1
        data,chains,rules=self.snapshots[name];family,protocol,port,destination,interface=flow
        if len(chains)!=len(data['chains']) or name!='nftables' and data['unsupported_objects']:
            return {'state':'unresolved','reason':'Ambiguous chains or unsupported iptables rows','outcomes':['unknown'],'references':[]}
        bases=[key for key,c in chains.items() if c['hook']=='input' and c['family'] in {'inet','ip' if family==4 else 'ip6'}]
        if not bases:
            result={'state':'unfiltered','reason':'No IP/inet INPUT base chain was reported in this view','outcomes':['accept'],'references':[]}
            self.cache[cache_key]=result;return result
        memo={};reasons=set();references=[];uncertainty=set();steps=0
        def interface_match(value,wildcard):
            if isinstance(value,dict) and set(value)=={'set'}:value=value['set']
            patterns=value if isinstance(value,list) else [value]
            if len(patterns)>128 or any(not isinstance(p,str) or len(p)>256 or p.startswith('@') or wildcard in p[:-1] for p in patterns):return None,'unresolved'
            if interface is None:return None,'interface'
            cache=(interface,tuple(patterns),wildcard)
            if cache not in self.interface_cache:
                matches=[any(name.startswith(p[:-1]) if p.endswith(wildcard) else name==p for p in patterns) for name in interface]
                self.interface_cache[cache]=True if matches and all(matches) else False if not any(matches) else None
            return self.interface_cache[cache],'interface'
        def address_match(value,source,rule):
            unknown=False
            if isinstance(value,str) and value.startswith('@'):
                sets=[s for s in data['sets'] if (s['family'],s['table'],s['name'])==(rule['family'],rule['table'],value[1:])]
                if not sets:return None,'unresolved'
                values=[n for s in sets for n in s['networks']];unknown=any(s['unsupported_elements'] for s in sets)
            else:
                if isinstance(value,list):return None,'unresolved'
                if isinstance(value,dict) and set(value)=={'set'}:
                    value=value['set']
                    if not isinstance(value,list):return None,'unresolved'
                values=value if isinstance(value,list) else [value]
                parsed=[network(v) for v in values];unknown=any(n is None for n in parsed);values=[n for n in parsed if n]
            nets=[ipaddress.ip_network(v) for v in values if ipaddress.ip_network(v).version==family]
            if source:
                if unknown:return None,'unresolved'
                if not nets:return False,None
                if any(n.prefixlen==0 for n in nets):return True,None
                return None,'source'
            if destination is None:return None,'unresolved'
            if any(ipaddress.ip_address(destination) in n for n in nets):return True,None
            return (None,'unresolved') if unknown else (False,None)
        def match(rule):
            values=[];causes=set()
            def add(value,cause='unresolved'):
                values.append(value)
                if value is None:causes.add(cause)
            for predicate in rule['matches']:
                negated=False
                if isinstance(predicate,str):
                    negated=predicate.startswith('! ');flag,_,value=predicate.removeprefix('! ').partition(' ')
                    if flag in {'-m','--comment','--reject-with'}:
                        if flag=='-m' and value in {'tcp','udp'}:add(protocol==value)
                        if flag=='-m' and value not in {'tcp','udp','conntrack','state','comment','multiport'}:add(None)
                        continue
                    if flag in {'-p','--protocol'}:result=value in {protocol,{'tcp':'6','udp':'17'}[protocol],'all','0'};cause=None
                    elif flag in {'--dport','--dports'}:
                        ranges=port_values(value);result=any(a<=port<=b for a,b in ranges) if ranges is not None else None;cause='unresolved'
                    elif flag in {'-s','--source','-d','--destination'}:result,cause=address_match(value,flag in {'-s','--source'},rule)
                    elif flag=='-i':result,cause=interface_match(value,'+')
                    elif flag in {'--ctstate','--state'}:
                        states=set(value.upper().split(','));result='NEW' in states if states<={'NEW','ESTABLISHED','RELATED','INVALID','UNTRACKED'} else None;cause='unresolved'
                    else:result=None;cause='unresolved'
                else:
                    left=predicate.get('left',{});op=predicate.get('op');value=predicate.get('right');result=None;cause='unresolved'
                    if op not in ('==','!=') or not isinstance(left,dict):add(None);continue
                    negated=op=='!='
                    payload=left.get('payload',{});meta=left.get('meta',{});ct=left.get('ct',{})
                    if isinstance(payload,dict) and payload.get('protocol') in ('icmp','icmpv6','icmp6','igmp','sctp','dccp','udplite'):return False,set()
                    if isinstance(payload,dict) and isinstance(payload.get('protocol'),str) and payload['protocol'] in {'ip','ip6','tcp','udp'}:
                        spec=payload['protocol'];field=payload.get('field')
                        if spec in {'ip','ip6'} and family!=({'ip':4,'ip6':6}[spec]):return False,set()
                        if spec in {'tcp','udp'} and spec!=protocol:return False,set()
                        if field in ('saddr','daddr'):result,cause=address_match(value,field=='saddr',rule)
                        elif field=='dport':
                            ranges=port_values(value);result=any(a<=port<=b for a,b in ranges) if ranges is not None else None
                        elif spec=='ip' and field=='protocol':result=protocol_test(value,{'tcp':6,'udp':17}[protocol])
                    elif isinstance(meta,dict) and meta.get('key')=='l4proto':
                        result=protocol_test(value,{'tcp':6,'udp':17}[protocol])
                    elif isinstance(meta,dict) and meta.get('key')=='nfproto':result=protocol_test(value,2 if family==4 else 10,family=True)
                    elif isinstance(meta,dict) and meta.get('key')=='iifname':result,cause=interface_match(value,'*')
                    elif isinstance(ct,dict) and ct.get('key')=='state':result=new_state(value)
                add(not result if negated and result is not None else result,cause)
            if any(v is False for v in values):return False,set()
            return (None,causes) if any(v is None for v in values) else (True,set())
        def chain(key,active):
            nonlocal steps
            if key in memo:return memo[key]
            if key in active or len(active)>=24 or key not in chains:
                reasons.add('Missing, cyclic or too-deep chain path');return {'unknown'}
            outcome={'return'}
            for i,rule in reversed(rules.get(key,[])):
                steps+=1;self.remaining-=1
                if steps>4096 or self.remaining<0:reasons.add('Rule evaluation budget reached');return {'unknown'}
                matches,causes=match(rule)
                if matches is False:continue
                raw=rule['original'];opaque=False;conditional=False;actions=[]
                if isinstance(raw,dict):
                    for item in raw['expr']:
                        kind=next(iter(item))
                        if kind in {'accept','drop','reject','return','jump','goto'}:actions.append((kind,item[kind]))
                        elif kind in {'limit','quota'}:conditional=True;reasons.add('State-dependent nft predicate: '+kind)
                        elif kind not in {'match','counter','log','comment'}:opaque=True;reasons.add('Unsupported nft expression: '+kind)
                else:
                    tokens=shlex.split(raw);targets=[tokens[j+1] for j,v in enumerate(tokens[:-1]) if v in {'-j','--jump','-g','--goto'}]
                    actions=[(v,None) for v in rule['verdicts']]
                    actions+=[(v['type'],{'target':v['target']}) for v in rule['links']]
                    opaque=bool(targets and not actions and targets[0] not in {'LOG','NFLOG'})
                    conditional=bool(rule['unsupported'])
                    if opaque:reasons.add('Unsupported iptables target')
                if opaque or len(actions)>1:branch={'unknown'}
                elif not actions:continue
                else:
                    kind,body=actions[0]
                    if kind in {'drop','reject'}:branch={'drop'}
                    elif kind in {'accept','return'}:branch={kind}
                    else:
                        target=(key[0],key[1],body['target']);branch=chain(target,active|{key})
                        if kind=='jump' and 'return' in branch:branch=(branch-{'return'})|outcome
                if conditional:
                    matches=None;causes.add('unresolved')
                    if not isinstance(raw,dict):reasons.add('Unsupported iptables match options')
                if causes:uncertainty.update(causes)
                if len(references)>=16:references.pop(0)
                references.append({'source':name,'rule_index':i})
                outcome=branch if matches is True else branch|outcome
            memo[key]=outcome;return outcome
        results=[]
        for key in bases:
            values=chain(key,set());policy=str(chains[key]['policy']).lower()
            values=(values-{'return'})|({policy} if policy in {'accept','drop'} else {'unknown'}) if 'return' in values else values
            results.append(values)
        if any('unknown' in v for v in results):state='unresolved'
        elif any(v=={'drop'} for v in results):state='blocked'
        elif all(v=={'accept'} for v in results):state='allowed'
        else:state='source_dependent' if uncertainty=={'source'} else 'interface_dependent' if uncertainty=={'interface'} else 'conditional' if uncertainty and uncertainty<={'source','interface'} else 'unresolved'
        result={'state':state,'reason':{'allowed':'All supported INPUT branches allow this new flow',
            'blocked':'A collected INPUT base chain blocks all supported branches',
            'source_dependent':'Source address determines conditional INPUT branches; inspect source rules/sets',
            'interface_dependent':'Incoming interface determines conditional INPUT branches; address assignment does not establish ingress',
            'conditional':'Source/interface predicates determine conditional INPUT branches; inspect their actual conditions',
            'unresolved':'; '.join(sorted(reasons)) or 'Conditions need an interface, address or unsupported match interpretation'}[state],
            'interpretation_notes':sorted(reasons),
            'outcomes':sorted(set().union(*results)),'references':references,'input_chains':[{'family':key[0],'table':key[1],'chain':key[2],'policy':chains[key]['policy']} for key in bases]}
        self.cache[cache_key]=result;return result

    def evaluate(self,row):
        backends=[]
        for name in ('nftables','iptables4' if row['family']==4 else 'iptables6'):
            if name not in self.snapshots:continue
            addresses=row['binding']['addresses']
            if row['binding']['kind']=='wildcard':addresses=[v for v in addresses if not ipaddress.ip_address(v['address']).is_loopback and not ipaddress.ip_address(v['address']).is_multicast]
            ingress=(self.loopbacks if row['binding']['kind']=='loopback' else self.ingress) or None
            flows=[(row['family'],row['protocol'],row['port'],v['address'],ingress) for v in addresses]
            if not flows or row['binding']['address_preview_capped']:
                destination=None if row['binding']['kind']=='wildcard' else row['local']['address'].split('%',1)[0]
                flows.append((row['family'],row['protocol'],row['port'],destination,ingress))
            try:values=[self.one(name,flow)|{'destination':flow[3],'candidate_ingress_interfaces':list(flow[4][:16]) if flow[4] else None,'ingress_preview_capped':bool(flow[4] and len(flow[4])>16)} for flow in flows]
            except (ValueError,KeyError,TypeError,IndexError,RecursionError):values=[{'state':'unresolved','reason':'Unsupported policy structure; no verdict inferred','references':[]}]
            states={v['state'] for v in values}
            state=next(iter(states)) if len(states)==1 else 'unresolved' if 'unresolved' in states else 'context_dependent'
            label={'allowed':'Allowed','blocked':'Blocked','source_dependent':'Source dependent','interface_dependent':'Interface dependent','conditional':'Source/interface dependent','context_dependent':'Address/interface dependent','unresolved':'Unresolved','unfiltered':'No INPUT chains'}[state]
            backends.append({'source':name,'state':state,'label':label,'scope':SCOPE,'flows':values[:8],'flow_preview_capped':len(values)>8})
        visible=backends
        legacy='iptables4' if row['family']==4 else 'iptables6'
        version=(self.sources[legacy+'_backend'].get('data') or {}).get('original','')
        if any(v['source']=='nftables' for v in backends) and '(nf_tables)' in version:visible=[v for v in backends if v['source']=='nftables']
        return {'scope':SCOPE,'backends':backends,'summary':(visible[0]['label'] if len(visible)==1 else '; '.join(('nft' if v['source']=='nftables' else v['source'])+': '+v['label'] for v in visible)) or 'Unavailable',
            'coverage':'Only collected IP/inet INPUT policy is assessed. Unreadable/legacy views, ingress/prerouting/NAT, forwarding, return paths and Internet reachability are separate; overlapping nft compatibility views are not corroboration.'}
