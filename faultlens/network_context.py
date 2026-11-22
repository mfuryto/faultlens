"""Bounded numeric address/route context and reported socket owner associations."""
from collections import Counter
from datetime import datetime,timezone
import ipaddress
import json
import re

from .commands import Command,CommandRunner
from .journal import unique_object,reject_constant,bounded_structure
from .sockets import parse as socket_rows
from .system_resources import read_source

LIMITS=[
    'Current network/PID namespaces and existing access only; independent sequential sources are not atomic.',
    'Addresses, link flags and route entries describe reported configuration, not usable connectivity, policy routing or Internet reachability.',
    'No route lookup, DNS/reputation query, packet capture, probe, blocking or configuration change runs.',
    'Socket ownership is reported by ss, possibly restricted. Exact unique row matches across snapshots constrain joins but cannot exclude socket/PID reuse.',
    'Cgroup service associations come from bounded current procfs samples; they do not verify membership at socket observation time or explain earlier activity.',
    'All accepted source fields and owners are retained without masking; unavailable sources remain independent coverage gaps.',
]


def text(value,limit=256):
    if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('Unsupported network label')
    return value


def address(value,family):
    if not isinstance(value,str) or '%' in value:raise ValueError('Unsupported address')
    parsed=ipaddress.ip_address(value)
    if parsed.version!=family:raise ValueError('Wrong address family')
    return value


def documents(raw):
    if len(raw.encode('utf-8'))>262144:raise ValueError('Network context size bound')
    data=json.loads(raw,object_pairs_hook=unique_object,parse_constant=reject_constant)
    bounded_structure(data)
    if not isinstance(data,list) or len(data)>256 or any(not isinstance(row,dict) for row in data):
        raise ValueError('Network context row bound')
    return data


def addresses(raw):
    rows=documents(raw);seen=set()
    for row in rows:
        index=row['ifindex'];text(row['ifname'],64);text(row.get('operstate','UNKNOWN'),32)
        if type(index) is not int or not 0<index<2**31 or index in seen:raise ValueError('Ambiguous interface identity')
        seen.add(index)
        flags=row.get('flags',[]);values=row.get('addr_info',[])
        if not isinstance(flags,list) or len(flags)>64 or not isinstance(values,list) or len(values)>64:raise ValueError('Address row limit')
        for flag in flags:text(flag,64)
        for value in values:
            family={'inet':4,'inet6':6}.get(value['family'])
            if family is None:raise ValueError('Unsupported address family')
            address(value['local'],family)
            if type(value['prefixlen']) is not int or not 0<=value['prefixlen']<=(32 if family==4 else 128):raise ValueError('Invalid prefix')
            text(value.get('scope','unknown'),32)
            for key in ('dadfailed','tentative','deprecated'):
                if key in value and type(value[key]) is not bool:raise ValueError('Unsupported address flag')
            address_flags=value.get('flags',[])
            if not isinstance(address_flags,list) or len(address_flags)>64:raise ValueError('Address flag limit')
            for flag in address_flags:text(flag,64)
    return rows


def routes(raw,family):
    rows=documents(raw)
    for row in rows:
        destination=row.get('dst','default')
        if not isinstance(destination,str):raise ValueError('Unsupported route destination')
        if destination!='default':
            network=ipaddress.ip_network(destination,strict=False)
            if network.version!=family:raise ValueError('Wrong route family')
        for key in ('dev','type','scope'):text(row.get(key,''),64)
        text(str(row.get('protocol','')),64)
        for key in ('gateway','prefsrc'):
            if key in row:address(row[key],family)
        hops=row.get('nexthops',[])
        if not isinstance(hops,list) or len(hops)>64:raise ValueError('Route next-hop bound')
        for hop in hops:
            text(hop.get('dev',''),64)
            if 'gateway' in hop:address(hop['gateway'],family)
        row['address_family']=family
    return rows


def owners(raw):
    if len(raw.encode('utf-8'))>262144:raise ValueError('Owner output bound')
    base=[];reported=[]
    pattern=re.compile(r'\("((?:[^"\\\x00-\x1f]|\\.){0,256})",pid=([0-9]{1,10}),fd=([0-9]{1,10})\)')
    for line in raw.splitlines():
        fields=line.split(None,6)
        if len(fields)<6:raise ValueError('Unsupported owned socket')
        base.append(' '.join(fields[:6]));suffix=fields[6] if len(fields)==7 else ''
        values=[]
        if suffix:
            if not suffix.startswith('users:(') or not suffix.endswith(')') or len(suffix)>8192:raise ValueError('Unsupported owner suffix')
            remaining=suffix[7:-1];matches=list(pattern.finditer(remaining))
            if not matches or len(matches)>16 or ','.join(match[0] for match in matches)!=remaining:raise ValueError('Unsupported owner list')
            for match in matches:
                pid,fd=int(match[2]),int(match[3])
                if not 0<pid<2**31 or fd>=2**31:raise ValueError('Unsupported reported owner identity')
                values.append({'reported_name':match[1],'pid':pid,'fd':fd})
        reported.append(values)
    rows=socket_rows('\n'.join(base))
    for row,line,values in zip(rows,raw.splitlines(),reported):row.update(original=line,owners=values)
    return rows


def collect(runner=None,*,sockets=None,sample_seconds=.1):
    runner=runner or CommandRunner();result={'sources':{},'limitations':list(LIMITS)}
    inquiries=[('addresses',Command.NETWORK_ADDRESSES,addresses),
               ('routes4',Command.NETWORK_ROUTES4,lambda raw:routes(raw,4)),
               ('routes6',Command.NETWORK_ROUTES6,lambda raw:routes(raw,6))]
    if sockets is not None:inquiries.append(('owners',Command.SOCKET_OWNERS,owners))
    for key,command,parse in inquiries:
        started=datetime.now(timezone.utc).isoformat();reply=runner.run(command)
        source={'state':'unavailable','rows':[],'command_state':reply.state,'returncode':reply.returncode,
                'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),'reason':'command_unsuccessful'}
        if reply.state=='completed' and reply.returncode==0:
            try:source.update(state='available',rows=parse(reply.stdout),reason=None)
            except (ValueError,KeyError,TypeError,UnicodeError,RecursionError):source['reason']='unsupported_or_over_limit_output'
        result['sources'][key]=source
    owned=result['sources'].get('owners',{});rows=owned.get('rows',[])
    if any(row['owners'] for row in rows):
        processes=read_source('processes',runner,sample_seconds);result['processes']=processes
        indexed={row['pid']:row for row in processes['rows']}
        for row in rows:
            for owner in row['owners']:
                process=indexed.get(owner['pid'])
                owner.update(service=process['service'] if process else None,
                    process_reference={'pid':process['pid'],'start_ticks':process['start_ticks']} if process else None,
                    association='reported_sequential_cgroup' if process and process['service'] else 'not_established')
    if sockets is not None:
        def key(row):return (row['protocol'],row['state'],row['local']['original'],row['peer']['original'],row['receive_queue'],row['send_queue'])
        counts=Counter(key(row) for row in sockets['rows']);owned_counts=Counter(key(row) for row in rows)
        unique={key(row):row for row in rows if owned_counts[key(row)]==1}
        for row in sockets['rows']:
            match=unique.get(key(row)) if counts[key(row)]==1 else None
            row.update(owners=match.get('owners',[]) if match else [],owner_reference=match['row_index'] if match else None,
                owner_state='reported_unique_snapshot_match' if match and match['owners'] else 'not_established')
    result['state']='available' if all(source['state']=='available' for source in result['sources'].values()) else 'partial' if any(source['state']=='available' for source in result['sources'].values()) else 'unavailable'
    if result.get('processes',{}).get('state') in {'partial','unavailable'} and result['state']=='available':result['state']='partial'
    return result
