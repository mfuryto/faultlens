"""Independent local port evidence with explicit limits on external accessibility."""
from datetime import datetime,timezone
import ipaddress
import time
from .commands import Command,CommandRunner,Result
from .models import report
from . import network_context as context
from . import firewall_rules,port_rules
from .system_resources import read_source

MAX_SECONDS=20
MAX_PORTS=128
LIMITS=[
    'Current network/PID namespaces, existing access and sequential bounded snapshots only; changes, socket/PID reuse and root/kernel compromise can invalidate associations.',
    'A listener, non-loopback/global address, default route, accept rule or NAT declaration does not establish Internet reachability. Provider/router policy, source restrictions, NAT, return paths and application health remain unverified.',
    'IPv4 and IPv6 are queried separately. Per-socket IPV6_V6ONLY is not collected; an IPv6 listener does not prove an IPv4 listener or vice versa.',
    'Policy references select compatible literal protocol/port predicates or unresolved/all-port conditions, not a packet simulation. Source/destination/interface/state restrictions, order, sets, jumps, later hooks and unsupported constructs still apply.',
    'nf_tables compatibility views can describe the same backend. Counts are retained rows/declarations, not independent services, unique ports or independent corroboration.',
    'DNAT/redirect can publish a port without a host listener. Container identity, other namespaces, dynamic maps/ipsets, kernel forwarding and upstream translations are not inferred.',
    'External verification is not performed. The suggested manual test must be separately authorized from an independent network and record source, target, family, protocol, UTC time and result. Never substitute a local or same-LAN test for Internet evidence.',
    'TCP connection success proves only that observed path at that time, not application health. UDP needs a valid protocol-specific request and matching response; silence or a successful send is inconclusive.',
    'No external probe, DNS query, packet capture, namespace entry, service/firewall write, counter reset, automatic installation, elevation or evidence export occurs.',
    'All accepted originals remain local without privacy masking; terminal controls are escaped. Unavailable sources and capped previews never become an all-clear.',
]


def listeners(raw,family):
    rows=context.owners(raw)
    for row in rows:
        if (row['protocol']=='tcp' and row['state']!='LISTEN' or row['protocol']=='udp' and row['state']!='UNCONN'
                or row['local']['port'] is None or row['local']['port']==0):raise ValueError('Unexpected listener state/port')
        for endpoint in (row['local'],row['peer']):
            host=endpoint['address'].split('%',1)[0]
            if host!='*' and ipaddress.ip_address(host).version!=family:raise ValueError('Unexpected listener family')
        row['family']=family
    return {'rows':rows,'original':raw}


def address_kind(value):
    address=ipaddress.ip_address(value)
    if address.is_loopback:return 'loopback'
    if address.is_unspecified:return 'wildcard'
    if address.is_link_local:return 'link-local'
    if address.is_multicast:return 'multicast'
    if address.is_global:return 'globally scoped; reachability unverified'
    return 'private/shared/special-use; upstream mapping unverified'


def binding(row,addresses):
    host,_,zone=row['local']['address'].partition('%');family=row['family'];wild=host=='*' or ipaddress.ip_address(host).is_unspecified
    kind='wildcard' if wild else address_kind(host);matches=[];total=0
    for interface in addresses:
        if zone and zone not in {interface['ifname'],str(interface['ifindex'])}:continue
        for value in interface.get('addr_info',[]):
            if value['family']!=('inet' if family==4 else 'inet6'):continue
            if not wild and ipaddress.ip_address(value['local'])!=ipaddress.ip_address(host):continue
            total+=1
            if len(matches)<32:matches.append({'address':value['local'],'kind':address_kind(value['local']),
                'ifname':interface['ifname'],'ifindex':interface['ifindex'],'operstate':interface.get('operstate'),
                'link_flags':interface.get('flags',[]),'address_flags':value.get('flags',[]),
                'tentative':value.get('tentative',False),'dadfailed':value.get('dadfailed',False),'deprecated':value.get('deprecated',False)})
    return {'kind':kind,'addresses':matches,'address_preview_capped':total>len(matches),
        'meaning':'This socket is bound to loopback; direct non-loopback delivery is not indicated. Proxies, translations or other listeners can expose a separate path.' if kind=='loopback' else
        'This socket accepts local delivery for its binding when the remaining path permits it. Review candidate addresses and policy; external accessibility is unverified.',
        'ipv4_via_ipv6':'Unknown; per-socket IPV6_V6ONLY not collected' if family==6 else 'not_applicable'}


def collect(runner=None,*,monotonic=time.monotonic):
    runner=runner or CommandRunner();started=monotonic();data=report('ports',[])
    data.update(sources={},ports=[],translations=[],policies=[],external_verification={'state':'not_performed','observations':[]},
        external_access='Unknown',limitations=list(LIMITS),bounds={'seconds':MAX_SECONDS,'port_previews':MAX_PORTS,'policy_references_per_port':32,'addresses_per_binding':32})
    def read(name,operation,parse):
        stamp=datetime.now(timezone.utc).isoformat();reply=operation() if monotonic()-started<MAX_SECONDS else Result('time_limit')
        source={'state':'unavailable','command_state':reply.state,'returncode':reply.returncode,'started_at':stamp,
            'finished_at':datetime.now(timezone.utc).isoformat(),'reason':'command_unsuccessful','data':None}
        if reply.state=='completed' and reply.returncode==0:
            try:
                if len(reply.stdout.encode('utf-8'))>262144:raise ValueError('Port source byte bound')
                source.update(state='available',data=parse(reply.stdout),reason=None)
            except (ValueError,KeyError,TypeError,UnicodeError,RecursionError,IndexError):source['reason']='unsupported_or_over_limit_output'
        data['sources'][name]=source
    for name,command,parse in (
        ('listeners4',Command.LISTENERS4,lambda raw:listeners(raw,4)),('listeners6',Command.LISTENERS6,lambda raw:listeners(raw,6)),
        ('addresses',Command.NETWORK_ADDRESSES,lambda raw:{'rows':context.addresses(raw),'original':raw}),
        ('routes4',Command.NETWORK_ROUTES4,lambda raw:{'rows':context.routes(raw,4),'original':raw}),
        ('routes6',Command.NETWORK_ROUTES6,lambda raw:{'rows':context.routes(raw,6),'original':raw}),
        ('nftables',Command.NFT_RULESET,firewall_rules.nft),('iptables4',Command.IPTABLES_SAVE,lambda raw:firewall_rules.iptables(raw,'ip')),
        ('iptables6',Command.IP6TABLES_SAVE,lambda raw:firewall_rules.iptables(raw,'ip6')),
        ('iptables4_backend',Command.IPTABLES_VERSION,lambda raw:{'original':raw}),
        ('iptables6_backend',Command.IP6TABLES_VERSION,lambda raw:{'original':raw})):
        read(name,lambda command=command:runner.run(command),parse)
    indexed,data['policies']=port_rules.index(data['sources'])
    translations=port_rules.translations(indexed,data['sources'])
    data['translations']=translations[:MAX_PORTS];data['translation_preview_capped']=len(translations)>MAX_PORTS
    addresses=(data['sources']['addresses']['data'] or {}).get('rows',[])
    all_rows=[(name,row) for name in ('listeners4','listeners6') for row in (data['sources'][name]['data'] or {}).get('rows',[])]
    data['port_preview_capped']=len(all_rows)>MAX_PORTS
    processes=None
    if any(row['owners'] for _,row in all_rows[:MAX_PORTS]):
        processes=read_source('processes',runner,.05) if monotonic()-started<MAX_SECONDS else {'state':'unavailable','rows':[],'reason':'time_limit'}
        data['processes']=processes
    process_index={row['pid']:row for row in (processes or {}).get('rows',[])}
    for source,row in all_rows[:MAX_PORTS]:
        family=row['family'];protocol=row['protocol'];port=row['local']['port'];owners=[]
        for original in row['owners']:
            process=process_index.get(original['pid']);owners.append({**original,'service':process.get('service') if process else None,
                'process_reference':{'pid':process['pid'],'start_ticks':process['start_ticks']} if process else None,
                'association':'Sequential current PID/cgroup association; socket/PID reuse and observation-time membership unverified'})
        refs,capped=port_rules.references(indexed,family,protocol,port)
        data['ports'].append({'source':source,'row_index':row['row_index'],'family':family,'protocol':protocol,'port':port,
            'local':row['local'],'socket':row,'binding':binding(row,addresses),'owners':owners,'policy_references':refs,'policy_preview_capped':capped,
            'external_access':'Unknown','external_test':'not_performed'})
    for translation in data['translations']:
        refs=[{'source':translation['source'],'rule_index':translation['rule_index'],'hooks':translation['hooks'],
            'association':'Translation declaration; packet path not established'}]
        translation['target_socket_indices']=[];translation['policy_preview_capped']=False
        target=translation['target_address'];port=translation['target_port']
        if target is not None and port is not None:
            family=ipaddress.ip_address(target).version
            protocols=[value for value,negated in translation['protocol_predicates'] if not negated] or ['tcp','udp']
            for protocol in protocols:
                candidates,capped=port_rules.references(indexed,family,protocol,port)
                translation['policy_preview_capped']|=capped
                for ref in candidates:
                    if any((r['source'],r['rule_index'])==(ref['source'],ref['rule_index']) for r in refs):continue
                    if len(refs)<32:refs.append(ref|{'association':'Candidate after translation; source/destination/path and order unresolved'})
                    else:translation['policy_preview_capped']=True
            for i,row in enumerate(data['ports']):
                if row['family']!=family or row['port']!=port or row['protocol'] not in protocols:continue
                host=row['local']['address'].split('%',1)[0]
                if host==target or row['binding']['kind']=='wildcard' and any(ipaddress.ip_address(v['address'])==ipaddress.ip_address(target) for v in row['binding']['addresses']):
                    translation['target_socket_indices'].append(i)
        translation['policy_references']=refs
    available=sum(s['state']=='available' for s in data['sources'].values())
    data['state']='available' if available==len(data['sources']) else 'partial' if available else 'unavailable'
    if processes and processes['state'] in {'partial','unavailable'} and data['state']=='available':data['state']='partial'
    data['collected_at']=datetime.now(timezone.utc).isoformat();return data
