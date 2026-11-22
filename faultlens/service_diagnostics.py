"""Shared service interpretation from reported manager state and retained messages."""
import re
import signal

RESULTS = {
    'exit-code': ('A service execution step returned an unsuccessful exit status.',
        'Read the failing step and its surrounding messages. Exit codes are program-specific; a nonzero value alone does not explain the cause.'),
    'signal': ('The manager reports termination by a signal.',
        'Inspect the reported signal and nearby records to determine whether a crash, administrator action or another event was reported.'),
    'core-dump': ('The manager reports termination with a core-dump result.',
        'Review crash messages and existing crash metadata with authorized access. This result does not prove that a usable core file was retained.'),
    'timeout': ('A service operation exceeded a timeout reported by the manager.',
        'Inspect startup, stop and readiness messages around the timeout. Check dependencies and workload before changing timeout values.'),
    'watchdog': ('The manager reports a service watchdog failure.',
        'Inspect watchdog and application messages in the same period. A missed watchdog does not establish a whole-server freeze.'),
    'oom-kill': ('The manager reports an out-of-memory kill affecting the service.',
        'Investigate the same period for kernel/cgroup OOM reports and retained memory measurements. Current free memory cannot establish past pressure.'),
    'start-limit-hit': ('The manager reports that the service start limit was reached.',
        'Find the earlier startup failure in the retained messages. Repeated starts and resetting the failure state do not repair that earlier problem.'),
    'resources': ('The manager reports a system-operation failure while preparing or running the service.',
        'Inspect the exact allocation or setup error. This result alone does not identify memory, process, descriptor or storage exhaustion.'),
    'protocol': ('The manager reports that the service did not meet its configured startup protocol.',
        'Compare readiness, process and PID messages with the intended service type before changing the unit.'),
    'exec-condition': ('The manager reports an unsuccessful execution condition.',
        'Inspect condition-command messages and the intended prerequisites. Do not treat a condition result as a confirmed application crash.'),
}
LOADS = {
    'not-found': ('The manager could not find the requested unit.',
        'Check the literal service name and expected installed package. Retained older logs do not prove the unit exists now.'),
    'masked': ('The manager reports that this unit is masked.',
        'Review the intended service policy and the recorded start attempt. Masking can be intentional; do not unmask automatically.'),
    'bad-setting': ('The manager reports an invalid required unit setting.',
        'Read the manager configuration error and compare the unit and drop-ins with the intended configuration.'),
    'error': ('The manager reports a unit-loading error.',
        'Read the unit-loading messages and check the intended unit/package configuration with existing access.'),
}


def termination(status):
    if status['state']!='available': return 'Main-process termination information is unavailable.'
    values=status['properties'];code=values['ExecMainCode'];number=values['ExecMainStatus']
    if code=='1':
        return 'Last reported main process exited with status '+number+'. Its meaning depends on the application and configured success statuses.'
    if code in {'2','3'}:
        try: label=signal.Signals(int(number)).name
        except ValueError: label='unknown signal'
        return 'Last reported main process '+('dumped core' if code=='3' else 'was killed')+' with signal '+number+' ('+label+'). This does not identify who sent it or prove a retained core file.'
    return 'No supported main-process termination interpretation; reported code '+code+', status '+number+'.'


def assessment(status):
    if status['state']!='available':
        return {'code':'unavailable','meaning':'Current service state could not be assessed.',
                'next_steps':['Check existing system-manager access and the literal service name. Available logs can still be investigated independently.']}
    values=status['properties'];load=values['LoadState'];result=values['Result']
    if load in LOADS: code=load;meaning,step=LOADS[load]
    elif result in RESULTS: code=result;meaning,step=RESULTS[result]
    elif values['ActiveState']=='failed':
        code='unclassified-failure';meaning='The manager reports a failed service, but its result has no supported interpretation.'
        step='Read the actual result, exit information and retained messages; no failure cause was assigned from the description.'
    else:
        code='no-current-failed-state';meaning='The manager snapshot does not report a failed active state. This does not establish application health or erase older failures.'
        step='Compare retained messages with their timestamps and invocation scope before treating an earlier error as a current problem.'
    if result and values['ActiveState']!='failed' and result in RESULTS:
        meaning+=' The current active state is '+values['ActiveState']+'; the last reported result is separate from current application impact.'
    return {'code':code,'meaning':meaning,'next_steps':[step],
            'reported':{key:values[key] for key in ('LoadState','ActiveState','SubState','Result','ExecMainCode','ExecMainStatus')}}


def invocation(record,unit,current):
    fields=record.get('unit_metadata',{})
    manager=record['metadata'].get('pid')=='1' and record['metadata'].get('comm')=='systemd' and record['metadata'].get('uid')=='0'
    identity=fields.get('_SYSTEMD_INVOCATION_ID') if fields.get('_SYSTEMD_UNIT')==unit else fields.get('INVOCATION_ID') if manager and fields.get('UNIT')==unit else None
    if not current or not isinstance(identity,str) or re.fullmatch('[0-9a-f]{32}',identity) is None:
        return 'Unverified invocation'
    return 'Same reported invocation ID' if identity==current else 'Different reported invocation ID'


def problem_rows(data):
    """Prioritize explained/error/warning records; keep every retained row accessible."""
    explanations={item['record_index']:item for item in data['explanations']}
    current=data['status']['properties'].get('InvocationID','')
    rows=[]
    for index,record in enumerate(data['journal_records']):
        explanation=explanations.get(index)
        priority=record['metadata'].get('priority','')
        urgent=priority in {'0','1','2','3','4'}
        title=explanation['title'] if explanation else 'Unclassified error/warning message' if urgent else 'Retained message; interpretation unknown'
        rows.append({'record_index':index,'title':title,'explained':explanation is not None,
            'invocation':invocation(record,data['unit'],current),
            'rank':0 if explanation else 1 if urgent else 2})
    return sorted(rows,key=lambda row:(row['rank'],row['record_index']))


def record_detail(data,index):
    from .investigation import utc
    record=data['journal_records'][index]
    explanation=next((item for item in data['explanations'] if item['record_index']==index),None)
    relation=invocation(record,data['unit'],data['status']['properties'].get('InvocationID',''))
    meaning=explanation['meaning'] if explanation else 'This is the retained original message. No supported specific meaning or underlying cause was assigned; severity metadata alone does not explain the failure.'
    step=explanation['next_step'] if explanation else 'Read surrounding messages and the manager result to find the first concrete failed operation. Check the application documentation for application-specific errors.'
    return {'Service':data['unit'],'Recorded UTC':utc(record['reference']['realtime_us']),
            'Recorded message':str(record['message']),'What it means':meaning,
            'Invocation scope':relation+'. Matching IDs associate reported metadata, not authenticity or cause.',
            'Current manager report':data['assessment']['meaning'],
            'What you can do':[step,'Open surrounding logs or investigate the recorded period. Current System/Network readings cannot establish earlier conditions.'],
            'Evidence limits':data['limitations']}


def followup_window(record):
    from .journal import MAX_REALTIME_US
    value=record['reference']['realtime_us']
    if type(value) is not int or not 0<=value<=MAX_REALTIME_US: raise ValueError('Invalid service record time')
    return max(0,value-120000000),min(MAX_REALTIME_US,value+120000000)
