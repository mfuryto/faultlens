"""Bounded read-only SSH report statistics, distinct from connections or attackers."""
from collections import Counter
from datetime import datetime,timezone
import ipaddress
import json
import re
import time

from .journal import BOOT_ID,MAX_BYTES,bounded_structure,entries,evidence_record,unique_object,reject_constant,validate_window
from .linux import LinuxSources
from .models import report
from .commands import CommandRunner
from .ssh import USER,PEER,supported_source

PAGE_SIZE=200
MAX_PAGES=50
MAX_EVIDENCE_BYTES=2*1024*1024
MAX_GROUPS=512
MAX_SECONDS=20
AUTH=re.compile(r'(?P<outcome>Failed|Accepted|Partial) (?P<method>password|publickey|keyboard-interactive(?:/pam)?|hostbased|gssapi-with-mic) for (?:invalid user )?(?P<username>'+USER+r') from '+PEER+r' ssh2(?:[: ][^\x00-\x1f\x7f-\x9f]*)?\n?')
INVALID=re.compile(r'Invalid user (?P<username>'+USER+r') from '+PEER+r'(?: \[preauth\])?\n?')
LIMITS=[
    'Counts describe explicit SSH log reports, not distinct connections, people, attacks or successful full sessions. Accepted and partial authentication are separate.',
    'Invalid-user and PAM context messages are not added to failed-authentication counts. Unknown methods/formats are unclassified, not guessed.',
    'Root-UID syslog records from sshd, sshd-session and sshd-auth only. Other sources, methods, namespaces and logging configurations can be missing.',
    'Exhausted means the bounded reader reached the end of currently accessible matching history, not complete logging since boot. Rotation, suppression, clock changes and concurrent journal changes remain unknown.',
    'No persistent counter, daemon, database, privilege change, DNS lookup or upload. Every counted record remains inspectable locally with original fields and cursor.',
    'Reported usernames and peer addresses are unverified input, not authenticated actor identities. Local root/kernel compromise can falsify evidence.',
]


def event(entry):
    if entry.message is None:return None
    match=AUTH.fullmatch(entry.message)
    kind='authentication' if match else 'invalid_user'
    if not match:match=INVALID.fullmatch(entry.message)
    if not match:return None
    try:peer=str(ipaddress.ip_address(match['peer']))
    except ValueError:return None
    port=int(match['port'])
    if not 1<=port<=65535:return None
    return {'kind':kind,'outcome':match['outcome'].lower() if kind=='authentication' else 'invalid_user',
        'method':match['method'] if kind=='authentication' else None,'username':match['username'],'peer':peer,'peer_port':port}


def page(raw,since,until,boot):
    if len(raw.encode('utf-8'))>MAX_BYTES:raise ValueError('SSH page byte bound')
    lines=[line for line in raw.splitlines() if line.strip()]
    if len(lines)>PAGE_SIZE:raise ValueError('SSH page row bound')
    result=[];seen=set()
    for line in lines:
        value=json.loads(line,object_pairs_hook=unique_object,parse_constant=reject_constant);bounded_structure(value)
        identity=value.get('_BOOT_ID') if isinstance(value,dict) else None
        if not isinstance(identity,str) or not BOOT_ID.fullmatch(identity) or boot is not None and identity!=boot:raise ValueError('Unexpected SSH boot')
        values,_,_=entries(line,identity,validator=lambda row:supported_source(row)
            and (since is None or row.realtime_us>=since) and row.realtime_us<=until)
        entry=values[0]
        if not entry.cursor or entry.cursor in seen:raise ValueError('Missing or duplicate SSH cursor')
        seen.add(entry.cursor);result.append(entry)
    return result


def collect(runner=None,*,sources=None,window='boot',since_us=None,until_us=None,boot_id=None,system_journal=False,clock=time.time,monotonic=time.monotonic):
    if window not in {'boot','hour','day','period'} or type(system_journal) is not bool:raise ValueError('Invalid SSH scope')
    validate_window(since_us,until_us)
    if boot_id is not None and (not isinstance(boot_id,str) or not BOOT_ID.fullmatch(boot_id)):raise ValueError('Invalid SSH boot filter')
    if window=='period' and (since_us is None or until_us is None):raise ValueError('SSH period requires both boundaries')
    if window!='period' and (since_us is not None or until_us is not None):raise ValueError('Explicit boundaries require SSH period')
    if window!='period':
        until_us=int(clock()*1000000)
        since_us=max(0,until_us-({'hour':3600,'day':86400}.get(window,0))*1000000) if window!='boot' else None
    validate_window(since_us,until_us)
    data=report('ssh',[])
    data.update(state='unavailable',window=window,requested_window={'since_realtime_us':since_us,'until_realtime_us':until_us},
        boot_filter=boot_id,journal_scope={'requested':'system' if system_journal else 'visible','completeness':'unknown'},
        scan_state='not_started',reason=None,pages_read=0,records_examined=0,records=[],totals=dict.fromkeys(('failed','accepted','partial','invalid_user')),users=[],peers=[],timeline=[],
        first_record=None,last_record=None,unclassified_records=0,
        bounds={'page_rows':PAGE_SIZE,'pages':MAX_PAGES,'evidence_bytes':MAX_EVIDENCE_BYTES,'groups_per_table':MAX_GROUPS,'seconds':MAX_SECONDS})
    data['limitations']=list(LIMITS)
    if window=='boot' and boot_id is None:
        try:
            identity=(sources or LinuxSources()).read('/proc/sys/kernel/random/boot_id',limit=64).strip()
            if not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',identity):raise ValueError('Invalid current boot')
            boot_id=identity.replace('-','');data['boot_filter']=boot_id
        except (OSError,ValueError,UnicodeError):data['reason']='current_boot_unavailable';return data
    runner=runner or CommandRunner()
    totals=Counter();tables={key:{} for key in ('users','peers','timeline')};seen=set();cursor=None;used=0;started=monotonic()
    bucket_seconds=60 if window=='hour' or since_us is not None and until_us-since_us<=3600000000 else 3600
    data['bucket_seconds']=bucket_seconds
    data['scan_state']='incomplete'
    for _ in range(MAX_PAGES):
        if monotonic()-started>=MAX_SECONDS:data['reason']='time_limit';break
        reply=runner.read_ssh_page(since_us,until_us,boot_id=boot_id,system=system_journal,cursor=cursor)
        data['last_command']={'state':reply.state,'returncode':reply.returncode}
        if reply.state!='completed' or reply.returncode!=0:data['reason']='command_unsuccessful';break
        try:
            values=page(reply.stdout,since_us,until_us,boot_id)
            if any(row.cursor in seen for row in values):raise ValueError('Repeated SSH cursor')
        except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):data['reason']='invalid_page';break
        data['pages_read']+=1
        for row in values:
            parsed=event(row);record=evidence_record(row);record['ssh_event']=parsed
            amount=len(json.dumps(record,ensure_ascii=True).encode('ascii'))
            keys={} if parsed is None else {'users':parsed['username'],'peers':parsed['peer'],
                'timeline':str(row.realtime_us//(bucket_seconds*1000000)*bucket_seconds)}
            if used+amount>MAX_EVIDENCE_BYTES:data['reason']='evidence_limit';break
            if any(key not in tables[name] and len(tables[name])>=MAX_GROUPS for name,key in keys.items()):data['reason']='group_limit';break
            used+=amount;seen.add(row.cursor);cursor=row.cursor;index=len(data['records']);data['records'].append(record)
            if data['first_record'] is None:data['first_record']=row.reference()
            data['last_record']=row.reference()
            if parsed is None:data['unclassified_records']+=1;continue
            outcome=parsed['outcome'];totals[outcome]+=1
            for name,key in keys.items():
                group=tables[name].setdefault(key,{'value':key,'counts':{},'methods':{},'first_realtime_us':row.realtime_us,
                    'last_realtime_us':row.realtime_us,'record_indices':[]})
                group['counts'][outcome]=group['counts'].get(outcome,0)+1
                if parsed['method']:group['methods'][parsed['method']]=group['methods'].get(parsed['method'],0)+1
                group['first_realtime_us']=min(group['first_realtime_us'],row.realtime_us)
                group['last_realtime_us']=max(group['last_realtime_us'],row.realtime_us);group['record_indices'].append(index)
        if data['reason']:break
        if len(values)<PAGE_SIZE:data.update(scan_state='exhausted',reason='accessible_query_exhausted');break
    else:data['reason']='page_limit'
    data['records_examined']=len(data['records']);data['totals']={key:totals[key] for key in ('failed','accepted','partial','invalid_user')}
    for name,groups in tables.items():data[name]=sorted(groups.values(),key=lambda row:int(row['value']) if name=='timeline' else (-row['counts'].get('failed',0),row['value']))
    data['state']='available' if data['scan_state']=='exhausted' else 'partial' if data['records'] else 'unavailable'
    if data['state']=='unavailable':data['totals']=dict.fromkeys(data['totals'])
    data['collected_at']=datetime.now(timezone.utc).isoformat()
    return data
