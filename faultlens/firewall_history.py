"""Fail2ban log observations; file-local timestamps never become guessed UTC."""
import hashlib
import json
import re
from .journal import unique_object,reject_constant,bounded_structure,entries,evidence_record
from .firewall_rules import network

ACTION=re.compile(r'\[([A-Za-z0-9_][A-Za-z0-9_.-]{0,63})\]\s+(Restore Ban|Ban|Unban|Found)\s+([0-9A-Fa-f:./]{1,64})(?:\s|$)')
ERROR=re.compile(r"Failed to execute (ban|unban|reban) jail '([A-Za-z0-9_][A-Za-z0-9_.-]{0,63})' action '([^'\x00-\x1f]{1,128})'")


def observation(record):
    message=record['message']
    if not isinstance(message,str):return None
    error=ERROR.search(message)
    if error:return {'jail':error[2],'action':'Action error ('+error[1]+')','address':None,'reported_action':error[3],
        'human_initiator':'Unknown','meaning':'Fail2ban reported an action execution error. This is jail-wide historical context; association with a particular current ban and current enforcement is unverified.'}
    match=ACTION.search(message)
    if not match or network(match[3]) is None:return None
    return {'jail':match[1],'action':match[2],'address':match[3],'human_initiator':'Unknown',
        'meaning':'A filter match was reported; this is not another distinct authentication failure or proof of a following ban.' if match[2]=='Found' else
            'A retained Fail2ban-labelled action report; automatic versus manual initiation and successful enforcement are unverified.'}


def journal(raw,since,until,boot):
    if len(raw.encode('utf-8'))>262144:raise ValueError('Journal byte bound')
    lines=[line for line in raw.splitlines() if line.strip()]
    if len(lines)>201:raise ValueError('Journal record bound')
    records=[];seen=set()
    for line in lines:
        value=json.loads(line,object_pairs_hook=unique_object,parse_constant=reject_constant);bounded_structure(value)
        if not isinstance(value,dict):raise ValueError('Invalid journal entry')
        identity=value.get('_BOOT_ID')
        if boot is not None and identity!=boot:raise ValueError('Unexpected boot')
        if value.get('_UID')!='0' or not (value.get('_SYSTEMD_UNIT')=='fail2ban.service' or
                value.get('UNIT')=='fail2ban.service' and value.get('_PID')=='1' and value.get('_COMM')=='systemd'):
            raise ValueError('Unexpected Fail2ban unit producer')
        parsed,_,_=entries(line,identity,validator=lambda row:(since is None or row.realtime_us>=since) and row.realtime_us<=until)
        row=parsed[0]
        if not row.cursor or row.cursor in seen:raise ValueError('Missing/duplicate journal cursor')
        seen.add(row.cursor);record=evidence_record(row);record['observation']=observation(record);records.append(record)
    return {'records':records[-200:],'record_limit_reached':len(records)>200,'scope':'selected_period_unit_tail'}


def log_tail(raw,previous=False):
    data=json.loads(raw,object_pairs_hook=unique_object,parse_constant=reject_constant);bounded_structure(data)
    expected='/var/log/fail2ban.log'+('.1' if previous else '')
    text=data['content']
    if data['path']!=expected or not isinstance(text,str) or len(text.encode('utf-8'))>32768:raise ValueError('Unexpected log tail')
    if data['sha256']!=hashlib.sha256(text.encode('utf-8')).hexdigest():raise ValueError('Tail digest mismatch')
    if type(data['tail_omitted_prefix']) is not bool or type(data['changed_during_read']) is not bool:raise ValueError('Invalid log metadata')
    records=[];lines=text.splitlines()
    for index,line in enumerate(lines[-200:]):
        record={'reference':{'source':'fail2ban-file-tail','boot_id':None,'realtime_us':None,'monotonic_us':None,'cursor_sha256':None,
            'path':expected,'tail_sha256':data['sha256'],'line_index':max(0,len(lines)-200)+index},
            'metadata':{'comm':'file log; producer unverified','uid':'','pid':'','transport':'file'},'message':line,'analysis_text_available':True}
        record['observation']=observation(record)
        stamp=re.match(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:[,.][0-9]+)?',line)
        record['reported_local_time']=stamp[0] if stamp else None;records.append(record)
    return {**data,'records':records,'record_limit_reached':len(lines)>200 or data['tail_omitted_prefix'],
        'scope':'fixed_file_tail_unfiltered_by_UTC_period','timezone':'unverified; no boot attribution'}
