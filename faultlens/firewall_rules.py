"""Normalize bounded firewall snapshots without evaluating arbitrary packet paths."""
import ipaddress
import json
import re
import shlex
from .journal import unique_object,reject_constant,bounded_structure

MAX_BYTES=131072
MAX_NFT_BYTES=196608
MAX_OBJECTS=2048


class InputLimitError(ValueError):
    """Fixed numeric diagnostics without including source-controlled rule content."""
    def __init__(self,unit,actual,limit):
        self.unit,self.actual,self.limit=unit,actual,limit
        super().__init__('Firewall '+unit+' limit exceeded')


def label(value):
    if not isinstance(value,str) or not 1<=len(value)<=256 or any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError('Unsupported firewall label')
    return value


def network(value):
    if isinstance(value,dict) and set(value)=={'prefix'}:
        value=value['prefix'];value=str(value['addr'])+'/'+str(value['len'])
    if isinstance(value,dict) and set(value)=={'elem'}:return network(value['elem']['val'])
    if not isinstance(value,str):return None
    try:return str(ipaddress.ip_network(value,strict=False))
    except ValueError:return None


def nft(raw):
    if len(raw.encode('utf-8'))>MAX_NFT_BYTES:raise InputLimitError('bytes',len(raw.encode('utf-8')),MAX_NFT_BYTES)
    data=json.loads(raw,object_pairs_hook=unique_object,parse_constant=reject_constant);bounded_structure(data)
    objects=data['nftables']
    if not isinstance(objects,list):raise ValueError('Unsupported firewall objects')
    if len(objects)>MAX_OBJECTS:raise InputLimitError('objects',len(objects),MAX_OBJECTS)
    chains=[];rules=[];sets=[];unknown=[];identities=set()
    for index,item in enumerate(objects):
        if not isinstance(item,dict) or len(item)!=1:raise ValueError('Unsupported nft object')
        kind,value=next(iter(item.items()))
        if kind=='metainfo':continue
        if kind not in {'table','chain','rule','set','element'}:unknown.append(index);continue
        if not isinstance(value,dict):raise ValueError('Unsupported nft fields')
        family=label(value['family']);table=label(value.get('table',value.get('name','')))
        if kind=='chain':
            if value.get('hook') is not None:label(value['hook'])
            if value.get('policy') is not None:label(value['policy'])
            if value.get('prio') is not None and type(value['prio']) not in {int,str}:raise ValueError('Invalid chain priority')
            name=label(value['name']);identity=(family,table,name)
            if identity in identities:raise ValueError('Duplicate chain identity')
            identities.add(identity)
            chains.append({'family':family,'table':table,'name':name,'hook':value.get('hook'),
                'priority':value.get('prio'),'policy':value.get('policy'),'original':value,'source_index':index})
        elif kind in {'set','element'}:
            name=label(value['name']);elements=value.get('elem',[])
            if not isinstance(elements,list) or len(elements)>MAX_OBJECTS:raise ValueError('Unsupported set elements')
            sets.append({'family':family,'table':table,'name':name,'networks':[v for member in elements if (v:=network(member)) is not None],
                'unsupported_elements':sum(network(member) is None for member in elements),'original':value,'source_index':index})
        elif kind=='rule':
            chain=label(value['chain']);expressions=value['expr']
            if not isinstance(expressions,list) or len(expressions)>64:raise ValueError('Unsupported rule expressions')
            verdicts=[];matches=[];set_refs=[];source_networks=[];links=[];counters=[];unsupported=[]
            for expression in expressions:
                if not isinstance(expression,dict) or len(expression)!=1:raise ValueError('Unsupported rule expression')
                key,body=next(iter(expression.items()))
                if key in {'accept','drop','reject','return'}:verdicts.append(key)
                elif key in {'jump','goto'}:
                    links.append({'type':key,'target':label(body['target'])})
                elif key=='match':
                    if not isinstance(body,dict):raise ValueError('Invalid match')
                    matches.append(body)
                    left=body.get('left',{});right=body.get('right');payload=left.get('payload',{}) if isinstance(left,dict) else {}
                    if not isinstance(payload,dict):unsupported.append(expression);continue
                    if body.get('op')=='==' and payload.get('field')=='saddr' and payload.get('protocol') in {'ip','ip6'}:
                        if isinstance(right,str) and right.startswith('@'):set_refs.append(label(right[1:]))
                        elif (address:=network(right)) is not None:source_networks.append(address)
                        else:unsupported.append(expression)
                elif key=='counter':
                    if isinstance(body,dict) and all(type(body.get(k)) is int and 0<=body[k]<2**64 for k in ('packets','bytes')):counters.append(body)
                    else:unsupported.append(expression)
                elif key not in {'log','comment'}:unsupported.append(expression)
            rules.append({'family':family,'table':table,'chain':chain,'handle':value.get('handle'),'verdicts':verdicts,
                'matches':matches,'set_refs':set_refs,'source_networks':source_networks,'links':links,'counters':counters,
                'unsupported':unsupported,'original':value,'source_index':index})
    return {'chains':chains,'rules':rules,'sets':sets,'unsupported_objects':unknown,'original':data}


def iptables(raw,family):
    if len(raw.encode('utf-8'))>MAX_BYTES or len(raw.splitlines())>MAX_OBJECTS:raise ValueError('Firewall text bound')
    chains=[];rules=[];table=None;unsupported=[]
    for index,line in enumerate(raw.splitlines()):
        if not line or line.startswith('#'):continue
        if len(line)>8192:raise ValueError('Firewall row bound')
        if line.startswith('*'):
            if table is not None:raise ValueError('Unclosed table')
            table=label(line[1:]);continue
        if line=='COMMIT':
            if table is None:raise ValueError('Unexpected commit')
            table=None;continue
        if table is None:raise ValueError('Rule outside a table')
        match=re.fullmatch(r':(\S+) (\S+) \[([0-9]{1,20}):([0-9]{1,20})\]',line)
        if match:
            chains.append({'family':family,'table':table,'name':label(match[1]),'policy':match[2],
                'hook':match[1].lower() if match[1] in {'INPUT','OUTPUT','FORWARD','PREROUTING','POSTROUTING'} else None,
                'packets':int(match[3]),'bytes':int(match[4]),'original':line,'source_index':index});continue
        tokens=shlex.split(line,posix=True);counters=[]
        if len(tokens)>128:raise ValueError('Firewall token bound')
        if tokens and re.fullmatch(r'\[[0-9]{1,20}:[0-9]{1,20}\]',tokens[0]):
            counts=tokens.pop(0)[1:-1].split(':');counters=[{'packets':int(counts[0]),'bytes':int(counts[1])}]
        if len(tokens)<2 or tokens[0]!='-A':unsupported.append(index);continue
        chain=label(tokens[1]);target=None;target_kind='jump';source_networks=[];conditions=[];extras=[];negated=False;i=2
        while i<len(tokens):
            token=tokens[i]
            if token=='!':negated=True;i+=1;continue
            if token in {'-s','--source','-d','--destination','-p','--protocol','--dport','--dports','--sport','--sports','-i','-o','--ctstate','--state','--match-set','--comment','-m','--reject-with'} and i+1<len(tokens):
                value=tokens[i+1];conditions.append(('! ' if negated else '')+token+' '+value)
                if token in {'-s','--source'} and not negated and (parsed:=network(value)) is not None:
                    if ipaddress.ip_network(parsed).version==({'ip':4,'ip6':6}[family]):source_networks.append(parsed)
                    else:extras.append('Source address family mismatch')
                if token=='--match-set':extras.append('ipset membership not inspected')
                negated=False;i+=2;continue
            if token in {'-j','--jump','-g','--goto'} and i+1<len(tokens):
                target=label(tokens[i+1]);target_kind='goto' if token in {'-g','--goto'} else 'jump';i+=2;continue
            extras.append(('! ' if negated else '')+token);negated=False;i+=1
        verdict=target.lower() if target in {'ACCEPT','DROP','REJECT','RETURN'} else None
        links=[{'type':target_kind,'target':target}] if target and target not in {'ACCEPT','DROP','REJECT','RETURN','LOG','NFLOG'} else []
        rules.append({'family':family,'table':table,'chain':chain,'handle':index,'verdicts':[verdict] if verdict else [],
            'matches':conditions,'set_refs':[],'source_networks':source_networks,'links':links,'counters':counters,
            'unsupported':extras,'original':line,'source_index':index})
    if table is not None:raise ValueError('Incomplete table')
    identities={(item['family'],item['table'],item['name']) for item in chains}
    for rule in rules:
        for link in rule['links']:
            if (rule['family'],rule['table'],link['target']) not in identities:rule['unsupported'].append('Unresolved target '+link['target'])
        rule['links']=[link for link in rule['links'] if (rule['family'],rule['table'],link['target']) in identities]
    return {'chains':chains,'rules':rules,'sets':[],'unsupported_objects':unsupported,'original':raw}


def fail2ban_status(raw,jail=None):
    if len(raw.encode('utf-8'))>(32768 if jail else MAX_BYTES):raise ValueError('Fail2ban byte bound')
    if jail is None:
        matches=re.findall(r'Jail list:\s*([^\r\n]*)',raw)
        if len(matches)!=1:raise ValueError('Unsupported jail listing')
        names=[name.strip() for name in matches[0].split(',') if name.strip()]
        if len(names)>128 or len(names)!=len(set(names)) or any(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}',name) is None for name in names):raise ValueError('Unsupported jail identity')
        return {'jails':names,'original':raw}
    if re.findall(r'Status for the jail:\s*([^\r\n]+)',raw)!=[jail]:raise ValueError('Unexpected jail status identity')
    fields={}
    for key in ('Currently failed','Total failed','Currently banned','Total banned','Banned IP list'):
        matches=re.findall(re.escape(key)+r':[^\S\r\n]*([^\r\n]*)',raw)
        if len(matches)!=1:raise ValueError('Unsupported jail status')
        value=matches[0].strip()
        if key=='Banned IP list':
            values=value.split()
            if len(values)>4096 or any(network(v) is None for v in values):raise ValueError('Unsupported ban addresses')
            fields['banned_addresses']=values
        else:
            if re.fullmatch('[0-9]{1,12}',value) is None:raise ValueError('Invalid jail counter')
            fields[key.lower().replace(' ','_')]=int(value)
    return dict(fields,jail=jail,original=raw,count_list_consistent=fields['currently_banned']==len(fields['banned_addresses']))
