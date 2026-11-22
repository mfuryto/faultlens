"""Bounded, read-only investigation of one literal system service and its journal."""
import json
import re

from .commands import CommandRunner, SERVICE_PROPERTIES, validate_service_unit
from . import journal
from .models import report

LIMITS = [
    'Current system-manager properties and accessible current-boot system journal only; no elevation.',
    'At most 200 retained unit records, 262144 native output bytes and two seconds per command.',
    'The unit query includes manager messages about the unit; it is not an all-system log search.',
    'Properties and logs are sequential snapshots. Logs may describe earlier attempts, not the current invocation.',
    'A reported error explains a message, not its underlying cause, current impact or evidence authenticity.',
    'No restart, reset-failed, profile loading, configuration change or report saving is performed.',
]


def properties(text, unit):
    if len(text.encode('utf-8'))>journal.MAX_BYTES: raise ValueError('Service property size limit')
    values={}
    for line in text.splitlines():
        key, separator, value=line.partition('=')
        if not separator or key not in SERVICE_PROPERTIES or key in values or len(value)>4096:
            raise ValueError('Unsupported service properties')
        values[key]=value
    if set(values)!=set(SERVICE_PROPERTIES) or values['Id']!=unit:
        raise ValueError('Incomplete or different service properties')
    for key in ('LoadState','ActiveState','SubState','Result'):
        if re.fullmatch(r'[a-z-]{0,64}',values[key]) is None: raise ValueError('Unsupported service state')
    for key in ('ExecMainCode','ExecMainStatus'):
        if re.fullmatch(r'[0-9]{1,10}',values[key]) is None: raise ValueError('Unsupported exit status')
    if values['InvocationID'] and re.fullmatch(r'[0-9a-f]{32}',values['InvocationID']) is None:
        raise ValueError('Unsupported invocation identity')
    return values


def records(text, unit):
    if len(text.encode('utf-8'))>journal.MAX_BYTES: raise ValueError('Service journal size limit')
    rows=[]
    for line in text.splitlines():
        if not line.strip(): continue
        if len(rows)>=201: raise ValueError('Service record count limit')
        item=json.loads(line,object_pairs_hook=journal.unique_object,parse_constant=journal.reject_constant)
        journal.bounded_structure(item)
        if not isinstance(item,dict) or not any(item.get(key)==unit for key in
                ('_SYSTEMD_UNIT','UNIT','OBJECT_SYSTEMD_UNIT','COREDUMP_UNIT')):
            raise ValueError('Journal record belongs to another service')
        rows.append(item)
    if not rows: return [],False,0
    boot=rows[0].get('_BOOT_ID')
    if not isinstance(boot,str): raise ValueError('Missing service journal boot identity')
    parsed,_,unsupported=journal.entries(text,boot)
    return [journal.evidence_record(item) for item in parsed[-200:]],len(parsed)>200,unsupported


def explain(unit, retained):
    """Small explicit message rules; every interpretation keeps its original index."""
    result=[]
    for index,record in enumerate(retained):
        message=record['message']
        if not record['analysis_text_available']: continue
        title=meaning=next_step=None
        if unit=='apparmor.service' and record['metadata']['comm'] in {'apparmor.systemd','apparmor.system','apparmor_parser'}:
            match=re.search(r"AppArmor parser error[^\n]*? in profile ([^\n]{1,512}?) at line ([0-9]{1,8}): Could not open '([^'\n]{1,512})'",message)
            if match:
                title='AppArmor could not open a profile include'
                meaning=('The parser reported that '+match[1]+' at line '+match[2]+' could not open '+match[3]+
                         '. This can prevent that profile from loading. The log does not distinguish a missing file from access or packaging problems, or prove that all AppArmor protection is off.')
                next_step='Check the reported include and profile against the installed package and intended local policy. Do not create an empty include or disable AppArmor merely to clear the error. Review current loaded profiles with aa-status using existing access.'
            elif re.search(r': Illegal number: [^\n]{1,80}$',message):
                title='AppArmor loader reported an invalid number'
                meaning='The loader reported a numeric operation with nonnumeric input. The configuration key and connection to other profile errors are not established.'
                next_step='Review the matching loader script/package version and its configuration. Keep this report separate from any parser/include error until their relationship is demonstrated.'
        if title is None:
            for signature,label,description,action in (
                ('No space left on device','Service message mentions no space available','A retained message contains No space left on device. Blocks, inodes, quotas or another resource may be involved; current capacity is not established.','Review filesystem capacity, inode and quota evidence for the reported destination before changing or deleting files.'),
                ('Permission denied','Service message mentions permission denied','A retained message contains Permission denied. Ownership, permissions, security policy and the exact operation need inspection; no cause is inferred.','Inspect the named operation and related messages with existing access before changing permissions or security policy.'),
                ('Address already in use','Service message mentions an address in use','A retained message contains Address already in use. The owning process and current endpoint state are not established.','Compare the recorded endpoint and service configuration with the current local socket snapshot before changing or stopping anything.'),
            ):
                if signature in message: title,meaning,next_step=label,description,action;break
        if title:
            result.append({'title':title,'meaning':meaning,'next_step':next_step,'record_index':index,
                           'reference':record['reference']})
    return result


def collect(unit, runner=None):
    validate_service_unit(unit)
    runner=runner or CommandRunner()
    data=report('service',[])
    data.update(unit=unit,state='unavailable',root_cause='Unknown',limitations=list(LIMITS))
    for key,read,parse in (
        ('status',runner.read_service_properties,properties),
        ('journal',runner.read_service_journal,records),
    ):
        result=read(unit)
        source={'state':'unavailable','command_state':result.state,'returncode':result.returncode,
                'reason':'command_unsuccessful','properties':{}} if key=='status' else {
                'state':'unavailable','command_state':result.state,'returncode':result.returncode,
                'reason':'command_unsuccessful','records':[],'record_limit_reached':False,'unsupported_messages':0}
        if result.state=='completed' and result.returncode==0:
            try:
                parsed=parse(result.stdout,unit)
                if key=='status':source['properties']=parsed
                else:source.update(zip(('records','record_limit_reached','unsupported_messages'),parsed))
                source.update(state='available',reason=None)
            except (ValueError,TypeError,UnicodeError,RecursionError): source['reason']='unsupported_or_over_limit_output'
        data[key]=source
    data['journal_records']=data['journal']['records']
    data['explanations']=explain(unit,data['journal_records'])
    available=sum(data[key]['state']=='available' for key in ('status','journal'))
    data['state']='available' if available==2 else 'partial' if available else 'unavailable'
    return data


def view(data):
    status=data['status']; logs=data['journal']; values=status['properties']
    if status['state']!='available': observed='Current service state could not be assessed.'
    elif values['LoadState']=='not-found': observed='The system manager reports that the unit was not found.'
    else:
        observed='System manager: '+values['ActiveState']+'/'+values['SubState']+'; result '+(values['Result'] or 'unspecified')+'.'
        if values['Result']=='exit-code':
            observed+=' The manager reports an unsuccessful service execution step.'
            if values['ExecMainCode']=='1' and values['ExecMainStatus']!='0':
                observed+=' Last reported main-process exit status: '+values['ExecMainStatus']+'.'
    if logs['state']!='available': coverage='Service logs unavailable; no fault or absence of faults can be established from this source.'
    elif not logs['records']: coverage='No retained service records returned. Access and completeness are unverified; this does not rule out a failure.'
    else: coverage=str(len(logs['records']))+' retained current-boot unit records; complete history and invocation association are unverified.'
    if logs['record_limit_reached']: coverage+=' Earlier records were omitted by the 200-record cap.'
    detail={'Observed':observed,'Description (not an error message)':values.get('Description','Unavailable'),
            'Last manager state change (UTC)':values.get('StateChangeTimestamp') or 'Not reported',
            'Journal coverage':coverage,
            'What it means':'Read the reported errors below and open Logs for surrounding messages. Service state alone does not establish impact or an underlying cause.'}
    for index,item in enumerate(data['explanations'][:20],1):
        from .investigation import utc
        record=data['journal_records'][item['record_index']]
        detail['Report '+str(index)+': '+item['title']]=[
            'Recorded UTC: '+utc(record['reference']['realtime_us']),
            'Message: '+str(record['message']),'Meaning: '+item['meaning'],'Next: '+item['next_step']]
    if len(data['explanations'])>20: detail['Additional reports']='More reports remain in records/original fields; only 20 explanations are shown here.'
    if not data['explanations']:
        detail['Message interpretation']='No supported specific error interpretation is available. This is not a no-error result; read the original records.'
    detail['What you can do']=['Read the explained reports and retained records. Unclassified messages remain available for investigation.',
        'If logs are unavailable, check existing system-journal access and retention. Faultlens never elevates or grants access.']
    detail['Evidence limits']=data['limitations']
    return detail


def render(data,out,*,details=False):
    from .presentation import line
    print('Faultlens - Service investigation (read-only): '+data['unit'],file=out)
    for key,value in view(data).items():
        line(out,key+':')
        for text in value if isinstance(value,list) else [value]: line(out,text,'  ')
    from .investigation import utc
    line(out,'Retained service log messages:')
    for record in data['journal_records']:
        line(out,utc(record['reference']['realtime_us'])+' | '+record['metadata']['comm']+' | '+str(record['message']),'  ')
    if details: line(out,'Technical source details: '+json.dumps(data,ensure_ascii=True))
