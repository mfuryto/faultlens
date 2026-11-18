"""Bounded terminal-login records; never infer complete sessions or authorization."""
from datetime import datetime,timezone
import ipaddress
import re

from .commands import Command,CommandRunner

MAX_ROWS=256
MAX_BYTES=262144
ROW=re.compile(r'(?P<username>\S{1,256})[ \t]+(?P<terminal>\S{1,128})[ \t]+'
    r'(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})[ \t]+(?P<time>[0-9]{2}:[0-9]{2})[ \t]+'
    r'(?P<idle>\.|old|\?|[0-9]{1,2}:[0-9]{2})[ \t]+(?P<pid>[0-9]{1,10}|\?)'
    r'(?:[ \t]+\((?P<source>[^()\r\n]{0,256})\))?[ \t]*\Z')
LIMITS=[
    'Reported local session records only; not every SSH connection, container or application login. Native session state is not proof of user activity.',
    'Records can be absent, stale or truncated by the native accounting source. Empty output does not establish that nobody is logged in.',
    'Reported usernames, terminals and source strings are not independently verified identities, authorization or proof of suspicious activity.',
    'UTC is requested from the native command. Source time precision is retained; accounting records and session creation times are not independently verified authentication times. Reads are non-atomic.',
    'Stored source text may be an IP address, hostname or local display. No DNS lookup or remote probe is performed.',
    'At most 256 records and 262144 command-output bytes; unsupported or over-limit output is unavailable, not a successful prefix.',
]


def parse(text):
    if not isinstance(text,str) or len(text.encode('utf-8'))>MAX_BYTES:raise ValueError('Login snapshot size')
    lines=text.split('\n')
    if lines[-1]=='':lines.pop()
    if len(lines)>MAX_ROWS:raise ValueError('Login snapshot record count')
    rows=[]
    for index,line in enumerate(lines):
        if len(line.encode('utf-8'))>4096 or any(ord(c)<32 and c!='\t' or 127<=ord(c)<=159 or c in '\u2028\u2029' for c in line):
            raise ValueError('Unsupported login record')
        match=ROW.fullmatch(line)
        if match is None:raise ValueError('Unsupported login layout')
        values=match.groupdict()
        timestamp=datetime.fromisoformat(values['date']+'T'+values['time']).replace(tzinfo=timezone.utc)
        pid=int(values['pid']) if values['pid']!='?' else None
        if pid is not None and pid>2**31-1:raise ValueError('Invalid session PID')
        idle=values['idle']
        if ':' in idle and int(idle.split(':')[1])>59:raise ValueError('Invalid idle time')
        source=values['source'] or None
        kind='not_reported';address=None
        if source is not None:
            try:address=str(ipaddress.ip_address(source));kind='ip_address'
            except ValueError:kind='local_display' if re.fullmatch(r':[0-9]+(?:\.[0-9]+)?',source) else 'reported_host_or_source'
        rows.append({'record_index':index,'username':values['username'],'terminal':values['terminal'],
            'login_time_utc':timestamp.isoformat(timespec='minutes'),'login_time_precision':'minute',
            'source_reported':source,'source_address':address,'source_kind':kind,'pid_reported':pid,
            'idle_reported':idle,'original':line})
    return rows


def collect_who(runner=None):
    started=datetime.now(timezone.utc).isoformat()
    result=(runner or CommandRunner()).run(Command.LOGIN_SESSIONS)
    source={'state':'unavailable','rows':[],'source':'who --users (LC_ALL=C, TZ=UTC; no --lookup)',
        'command_state':result.state,'returncode':result.returncode,'reason':'command_unsuccessful',
        'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),
        'completeness':'unknown','limitations':list(LIMITS)}
    if result.state=='completed' and result.returncode==0:
        try:
            source['rows']=parse(result.stdout)
            source.update(state='available',reason='records_reported' if source['rows'] else 'no_records_reported')
        except (ValueError,UnicodeError):
            source['reason']='unsupported_or_over_limit_output'
            try:
                if len(result.stdout.encode('utf-8'))<=MAX_BYTES:source['unparsed_output']=result.stdout
            except UnicodeError:pass
    source['finished_at']=datetime.now(timezone.utc).isoformat()
    return source


def attach(data,runner=None):
    data['login_sessions']=collect(runner)
    data['collected_at']=data['login_sessions']['finished_at']
    return data


def source_label(row):
    value=row['source_reported']
    if value is None:return 'Not reported'
    if row['source_kind']=='reported_host_or_source':return value+' (reported; not resolved)'
    if row['source_kind']=='local_display':return value+' (local display)'
    return value


def detail(row):
    return {'Observed':row['username']+' on '+row['terminal'],
        'Reported login time UTC':(row['login_time_utc'] or 'Not reported')+' ('+row['login_time_precision']+' precision)',
        'Reported source':source_label(row),
        'Reported session state':row.get('session_state_reported','Not reported by accounting source'),
        'Reported session type/class':row.get('session_type_reported','Not reported')+' / '+row.get('session_class_reported','Not reported'),
        'What it means':'A native session/accounting record, not proof that the user is currently active, authorized or the cause of a fault.',
        'What you can do':['Compare the reported session with expected administrative activity. No logout, process signal, lookup or configuration change is performed.'],
        'Evidence limits':list(LIMITS),'Technical details':row}


SESSION_ID=re.compile(r'(?:[0-9]{1,10}|c[0-9]{1,10})\Z')
PROPERTIES={'Id','Name','User','TTY','Timestamp','RemoteHost','State','Type','Class'}


def listed_ids(text):
    if len(text.encode('utf-8'))>MAX_BYTES:raise ValueError('Session listing size')
    result=[]
    for line in text.splitlines():
        if not line.strip():continue
        fields=line.split()
        if len(fields)<3 or not SESSION_ID.fullmatch(fields[0]) or fields[0] in result:raise ValueError('Unsupported session listing')
        if any(ord(c)<32 and c!='\t' or 127<=ord(c)<=159 or c in '\u2028\u2029' for c in line):raise ValueError('Unsafe session listing')
        result.append(fields[0])
        if len(result)>64:raise ValueError('Session listing limit')
    return result


def parse_properties(text,identities):
    if len(text.encode('utf-8'))>MAX_BYTES:raise ValueError('Session property size')
    groups=[];values={}
    for line in text.split('\n'):
        if not line:
            if values:groups.append(values);values={}
            continue
        if len(line)>4096 or any(ord(c)<32 or 127<=ord(c)<=159 or c in '\u2028\u2029' for c in line):raise ValueError('Unsafe session property')
        key,separator,value=line.partition('=')
        if not separator or key not in PROPERTIES or key in values:raise ValueError('Unsupported session property')
        values[key]=value
    if values:groups.append(values)
    if len(groups)!=len(identities) or {v.get('Id') for v in groups}!=set(identities):raise ValueError('Incomplete session snapshot')
    rows=[]
    for index,values in enumerate(groups):
        if set(values)!=PROPERTIES:raise ValueError('Missing session property')
        if not re.fullmatch(r'[0-9]{1,10}',values['User']) or int(values['User'])>2**32-1:raise ValueError('Invalid session UID')
        if any(len(values[key])>256 for key in ('Name','TTY','RemoteHost','State','Type','Class')):raise ValueError('Session field limit')
        timestamp=None;precision='unknown'
        if values['Timestamp'] not in {'','n/a'}:
            match=re.fullmatch(r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]{1,6})? UTC',values['Timestamp'])
            if match is None:raise ValueError('Unsupported session time')
            stamp=datetime.fromisoformat(match[2]+(match[3] or '')).replace(tzinfo=timezone.utc)
            if stamp.weekday()!=('Mon','Tue','Wed','Thu','Fri','Sat','Sun').index(match[1]):raise ValueError('Inconsistent session time')
            timestamp=stamp.isoformat();precision='fractional second' if match[3] else 'second'
        remote=values['RemoteHost'] or None;address=None;kind='not_reported'
        if remote:
            try:address=str(ipaddress.ip_address(remote));kind='ip_address'
            except ValueError:kind='reported_host_or_source'
        rows.append({'record_index':index,'username':values['Name'] or 'Name not reported (UID '+values['User']+')',
            'username_reported':values['Name'] or None,'uid_reported':int(values['User']),
            'terminal':values['TTY'] or 'Not reported','terminal_reported':values['TTY'] or None,
            'login_time_utc':timestamp,'login_time_precision':precision,'source_reported':remote,
            'source_address':address,'source_kind':kind,'session_id':values['Id'],
            'session_state_reported':values['State'],'session_type_reported':values['Type'],
            'session_class_reported':values['Class'],'original':values})
    return rows


def collect_logind(runner):
    started=datetime.now(timezone.utc).isoformat()
    service=runner.run(Command.LOGIN_SESSION_SERVICE)
    if service.state!='completed' or service.returncode!=0 or service.stdout.strip()!='active':
        return {'state':'unavailable','rows':[],'source':'existing local logind',
            'command_state':service.state,'returncode':service.returncode,'reason':'existing_logind_not_confirmed_active',
            'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),
            'completeness':'unknown','limitations':list(LIMITS)}
    result=runner.run(Command.LOGIN_SESSION_LIST)
    source={'state':'unavailable','rows':[],'source':'local loginctl list-sessions/show-session (LC_ALL=C, TZ=UTC)',
        'command_state':result.state,'returncode':result.returncode,'reason':'listing_unsuccessful',
        'started_at':started,'finished_at':started,'completeness':'unknown','limitations':list(LIMITS)}
    try:
        if result.state=='completed' and result.returncode==0:
            identities=listed_ids(result.stdout)
            if not identities:source.update(state='available',reason='no_records_reported')
            else:
                result=runner.read_login_session_properties(identities)
                source.update(command_state=result.state,returncode=result.returncode,reason='properties_unsuccessful')
                if result.state=='completed' and result.returncode==0:
                    source['rows']=parse_properties(result.stdout,identities)
                    source.update(state='available',reason='records_reported')
    except (ValueError,UnicodeError):
        source['reason']='unsupported_or_over_limit_output'
        try:
            if len(result.stdout.encode('utf-8'))<=MAX_BYTES:source['unparsed_output']=result.stdout
        except UnicodeError:pass
    source['finished_at']=datetime.now(timezone.utc).isoformat()
    return source


def collect(runner=None):
    runner=runner or CommandRunner()
    primary=collect_logind(runner)
    if primary['state']=='available' and primary['rows']:return primary
    fallback=collect_who(runner)
    if fallback['state']=='available':
        fallback['other_source_evidence']=primary
        fallback['fallback_used']=True
        fallback['limitations'].append('Fallback accounting source used because logind was unavailable or returned no records; sources are not merged or assumed equivalent.')
        if primary['state']!='available':fallback['state']='partial'
        return fallback
    primary['other_source_evidence']=fallback
    if primary['state']=='available':return primary
    primary['reason']='no_usable_session_source'
    return primary


def login_label(row):
    return row['login_time_utc'].replace('+00:00','Z') if row['login_time_utc'] else 'Not reported'
