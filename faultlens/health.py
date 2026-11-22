"""Read-only operational snapshot and a separately scoped failed-service listing."""
import re
import math
from datetime import datetime,timezone

from .commands import Command,CommandRunner
from .collectors import status,check
from .models import report

LIMITS=[
    'System-manager service units visible through existing access only; not user units or all host workloads.',
    'A failed unit is an observed manager state, not verified service impact or the cause of an incident.',
    'An empty successful listing does not establish a healthy server; collection is non-atomic.',
    'At most 128 service rows, 4096 bytes per row and the native command time/output limits.',
    'No unit-controlled text is executed; no restart, reset-failed, elevation or configuration change occurs.',
]


def parse_failed_services(text):
    if len(text.encode('utf-8'))>262144: raise ValueError('Failed-service output limit')
    lines=text.split('\n')
    if lines and lines[-1]=='': lines.pop()
    if len(lines)>128: raise ValueError('Failed-service row limit')
    rows=[];seen=set()
    for line in lines:
        if len(line.encode('utf-8'))>4096: raise ValueError('Failed-service line limit')
        fields=line.split(None,4)
        if len(fields)!=5: raise ValueError('Unsupported service output')
        unit,load,active,sub,description=fields
        if (len(unit)>255 or re.fullmatch(r'(?:[A-Za-z0-9:_.@-]|\\x[0-9a-fA-F]{2})+\.service',unit) is None
                or load not in {'loaded','not-found','error','bad-setting','masked','stub'}
                or active!='failed' or sub!='failed' or unit in seen):
            raise ValueError('Unsupported failed-service row')
        seen.add(unit)
        rows.append({'unit':unit,'load':load,'active':active,'sub':sub,'description':description,'original':line})
    return rows


def failed_services(runner):
    started=datetime.now(timezone.utc).isoformat()
    result=runner.run(Command.FAILED_SERVICES)
    source={'state':'unavailable','command_state':result.state,'returncode':result.returncode,
            'source':'systemctl list-units --state=failed --type=service','rows':[],
            'started_at':started,'finished_at':datetime.now(timezone.utc).isoformat(),
            'reason':'command_unsuccessful','limitations':list(LIMITS)}
    if result.state=='completed' and result.returncode==0:
        try:
            source['rows']=parse_failed_services(result.stdout)
            source.update(state='available',reason=None)
        except (ValueError,UnicodeError): source['reason']='unsupported_or_over_limit_output'
    return source


def collect(sources=None,runner=None,*,sample_seconds=0.1,preservation=False):
    if type(sample_seconds) not in {int,float} or not math.isfinite(sample_seconds) or not 0.05<=sample_seconds<=1 or type(preservation) is not bool:
        raise ValueError('Invalid health collection options')
    runner=runner or CommandRunner()
    observations=status(sources,runner,sample_seconds)+check(sources,runner)
    if preservation:
        from .preservation import assess
        observations.extend(assess(sources,runner))
    data=report('health',observations)
    data['failed_services']=failed_services(runner)
    from .system_resources import attach
    attach(data,runner,sample_seconds)
    data['limitations'].extend(LIMITS)
    return data
