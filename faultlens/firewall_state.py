"""Independent read-only firewall/Fail2ban snapshots and qualified correspondence."""
from datetime import datetime,timezone
import ipaddress
import re
import time
from .commands import Command,CommandRunner,Result
from .models import report
from .journal import BOOT_ID,validate_window
from .linux import LinuxSources
from . import firewall_rules as rules
from . import firewall_history as history

MAX_JAILS=8
MAX_BANS=128
MAX_SECONDS=20
LIMITS=[
    'Current network namespace and existing access only. Independent sequential sources are not an atomic or complete policy snapshot.',
    'A drop/reject expression or default policy is conditional on reaching the chain and matching its predicates. Full packet paths, dynamic maps/sets, ipsets, bridges, other namespaces and upstream policy can remain unresolved.',
    'Accept and log statements do not establish a final packet verdict. IPv4/IPv6, NAT, forwarding, connection tracking and chain priorities matter. No external reachability verdict is made.',
    'Rule counters describe reported packets/bytes since an unverified reset, not connections, distinct clients or authentication attempts.',
    'Fail2ban-reported bans, same-address block expressions and retained logs are separate evidence. Correspondence does not verify action ownership, a traversed packet path or effective blocking.',
    'A Fail2ban report can follow automatic or manual commands. Human initiator is Unknown without independent audit evidence; names/comments alone do not establish provenance.',
    'Current jail settings and lifetime counters do not establish historical thresholds, actual expiry or counts since boot. A ban log is not proof the configured action succeeded.',
    'Copied/repeated file and journal messages are not independent corroboration or necessarily distinct incidents.',
    'Fixed file tails are not filtered by the selected UTC window: local timestamps, rotation and boot attribution remain unverified. Missing sources or unmatched entries never become an all-clear.',
    'All originals remain local without masking; hostile terminal controls are escaped. No ban/unban, firewall write, counter reset, trace, probe, DNS lookup, database or daemon is introduced.',
]


def collect(runner=None,*,sources=None,window='day',since_us=None,until_us=None,boot_id=None,system_journal=False,clock=time.time,monotonic=time.monotonic):
    if window not in {'boot','hour','day','period'} or type(system_journal) is not bool:raise ValueError('Invalid firewall scope')
    validate_window(since_us,until_us)
    if boot_id is not None and (not isinstance(boot_id,str) or not BOOT_ID.fullmatch(boot_id)):raise ValueError('Invalid firewall boot filter')
    if window=='period' and (since_us is None or until_us is None):raise ValueError('Period requires both boundaries')
    if window!='period' and (since_us is not None or until_us is not None):raise ValueError('Explicit bounds require period')
    if window!='period':
        until_us=int(clock()*1000000);since_us=max(0,until_us-{'hour':3600,'day':86400}.get(window,0)*1000000) if window!='boot' else None
    validate_window(since_us,until_us)
    data=report('firewall',[]);data.update(window=window,boot_filter=boot_id,
        requested_window={'since_realtime_us':since_us,'until_realtime_us':until_us},
        journal_scope={'requested':'system' if system_journal else 'visible','completeness':'unknown'},
        sources={},jails=[],correspondences=[],records=[],human_initiator='Unknown',packet_verdict='Unknown',
        bounds={'seconds':MAX_SECONDS,'jails':MAX_JAILS,'ban_previews':MAX_BANS,'matches_per_ban':8,'source_bytes':rules.MAX_BYTES,'nft_source_bytes':rules.MAX_NFT_BYTES},limitations=list(LIMITS))
    boot_state='available'
    if window=='boot' and boot_id is None:
        try:
            value=(sources or LinuxSources()).read('/proc/sys/kernel/random/boot_id',limit=64).strip()
            if re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value) is None:raise ValueError('Invalid kernel boot')
            boot_id=value.replace('-','');data['boot_filter']=boot_id
        except (OSError,ValueError,UnicodeError):boot_state='unavailable'
    runner=runner or CommandRunner();started=monotonic()
    def read(name,operation,parse):
        stamp=datetime.now(timezone.utc).isoformat()
        reply=operation() if monotonic()-started<MAX_SECONDS else Result('time_limit')
        source={'state':'unavailable','command_state':reply.state,'returncode':reply.returncode,
            'stderr':reply.stderr,
            'started_at':stamp,'finished_at':datetime.now(timezone.utc).isoformat(),'reason':'command_unsuccessful','data':None}
        if reply.state=='completed' and reply.returncode==0:
            try:
                if len(reply.stdout.encode('utf-8'))>262144:raise ValueError('Capture byte bound')
                source.update(state='available',data=parse(reply.stdout),reason=None)
            except rules.InputLimitError as error:source.update(reason='input_limit_exceeded',input_limit={'unit':error.unit,'actual':error.actual,'limit':error.limit})
            except (ValueError,KeyError,TypeError,UnicodeError,RecursionError):source['reason']='unsupported_or_over_limit_output'
        data['sources'][name]=source;return source
    def plain(raw):
        if len(raw.encode('utf-8'))>rules.MAX_BYTES:raise ValueError('Text bound')
        return {'original':raw}
    def setting_value(raw):
        if len(raw.encode('utf-8'))>4096:raise ValueError('Setting byte bound')
        value=raw.strip()
        return {'original':raw,'value':int(value) if re.fullmatch(r'(?:[0-9]{1,12}|-1)',value) else None}
    for name,command,parse in (('nftables',Command.NFT_RULESET,rules.nft),
            ('iptables4',Command.IPTABLES_SAVE,lambda raw:rules.iptables(raw,'ip')),
            ('iptables6',Command.IP6TABLES_SAVE,lambda raw:rules.iptables(raw,'ip6')),
            ('iptables4_backend',Command.IPTABLES_VERSION,plain),('iptables6_backend',Command.IP6TABLES_VERSION,plain),
            ('ufw',Command.UFW_STATUS,plain),('fail2ban',Command.FAIL2BAN_STATUS,rules.fail2ban_status)):
        read(name,lambda command=command:runner.run(command),parse)
    status=data['sources']['fail2ban']
    data['jail_limit_reached']=False
    if status['state']=='available':
        names=status['data']['jails'];data['jail_limit_reached']=len(names)>MAX_JAILS
        for name in names[:MAX_JAILS]:
            item=read('jail:'+name,lambda:runner.read_fail2ban(name,'status'),lambda raw:rules.fail2ban_status(raw,name))
            if item['state']!='available':continue
            jail=item['data'];jail['source']='jail:'+name;jail['settings']={}
            for field in ('maxretry','findtime','bantime','actions'):
                setting=read('jail:'+name+':'+field,lambda field=field:runner.read_fail2ban(name,field),setting_value)
                jail['settings'][field]=setting
            data['jails'].append(jail)
    for previous in (False,True):
        source=read('log_previous' if previous else 'log_current',lambda:runner.read_fail2ban_log(previous),lambda raw:history.log_tail(raw,previous))
        if source['state']=='available':data['records'].extend(source['data']['records'])
    read('fail2ban_journal',lambda:runner.read_fail2ban_journal(since_us,until_us,boot_id=boot_id,system=system_journal) if boot_state=='available' else Result('boot_unavailable'),
        lambda raw:history.journal(raw,since_us,until_us,boot_id))
    source=data['sources']['fail2ban_journal']
    if source['state']=='available':data['records'].extend(source['data']['records'])
    data['ban_preview_limit_reached']=False
    indexed=block_index(data['sources'])
    for jail in data['jails']:
        for address in jail['banned_addresses']:
            if len(data['correspondences'])>=MAX_BANS:data['ban_preview_limit_reached']=True;break
            matches=correspondence(indexed,address)
            data['correspondences'].append({'jail':jail['jail'],'address':address,'source':jail['source'],'matches':matches,
                'match_preview_limit_reached':len(matches)>=8,
                'assessment':'Same-address block expression observed' if matches else 'No supported correspondence established',
                'initiator_reported':'Fail2ban jail status','human_initiator':'Unknown','enforcement':'Unverified; conditional rules and path require review'})
    available=sum(source['state']=='available' for source in data['sources'].values())
    data['state']='available' if available==len(data['sources']) else 'partial' if available else 'unavailable'
    data['collected_at']=datetime.now(timezone.utc).isoformat();return data


def block_index(sources):
    """Index each prefix once and cap stored references, even for shared large sets."""
    indexed={}
    for source_name in ('nftables','iptables4','iptables6'):
        source=sources[source_name]
        if source['state']!='available':continue
        snapshot=source['data'];sets={}
        for position,item in enumerate(snapshot['sets']):sets.setdefault((item['family'],item['table'],item['name']),[]).append((position,item))
        for index,rule in enumerate(snapshot['rules']):
            if not set(rule['verdicts'])&{'drop','reject'}:continue
            observed=list(rule['source_networks']);set_indices=[]
            for name in rule['set_refs']:
                for position,item in sets.get((rule['family'],rule['table'],name),[]):
                    observed+=item['networks'];set_indices.append(position)
            reference={'source':source_name,'rule_index':index,'set_indices':set_indices}
            for value in observed:
                refs=indexed.setdefault(value,[])
                if len(refs)<8 and reference not in refs:refs.append(reference)
    return [(ipaddress.ip_network(value),refs) for value,refs in indexed.items()]


def correspondence(indexed,address):
    candidate=ipaddress.ip_network(address,strict=False);matches=[]
    for value,references in indexed:
        if candidate.version==value.version and candidate.subnet_of(value):
            for reference in references:
                if reference not in matches:matches.append(reference)
                if len(matches)>=8:return matches
    return matches
