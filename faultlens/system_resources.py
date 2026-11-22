"""Independent resource-source contracts; no native fallback after failed workers."""
import json
import math
from types import SimpleNamespace
from datetime import datetime,timezone

from .commands import CommandRunner,validate_service_unit
from .journal import unique_object,reject_constant,bounded_structure


def counter(value):
    if type(value) is not int or not 0<=value<=2**64-1:raise ValueError('Invalid resource counter')


def finite(value):
    if type(value) not in {int,float} or not math.isfinite(value) or value<0:raise ValueError('Invalid resource measurement')


def validate(data,kind):
    if (not isinstance(data,dict) or data.get('schema_version')!=1 or data.get('command')!=kind
            or data.get('state') not in {'available','partial'} or not isinstance(data.get('coverage'),dict)
            or not isinstance(data.get('limitations'),list) or any(not isinstance(value,str) for value in data['limitations'])
            or not isinstance(data.get('rows'),list) or len(data['rows'])>(512 if kind=='processes' else 256)):
        raise ValueError('Invalid resource report')
    identities=set()
    if kind=='processes':
        if type(data.get('clock_ticks_per_second')) is not int or not 0<data['clock_ticks_per_second']<=1000000:
            raise ValueError('Invalid process clock unit')
    for row in data['rows']:
        if not isinstance(row,dict):raise ValueError('Invalid resource row')
        if kind=='processes':
            counter(row['pid'])
            if not 0<row['pid']<2**31 or row['pid'] in identities:raise ValueError('Invalid process identity')
            identities.add(row['pid'])
            for key in ('cpu_ticks','start_ticks','rss_bytes','virtual_bytes'):counter(row[key])
            if not isinstance(row['name'],str) or not 0<len(row['name'])<=256:raise ValueError('Invalid process name')
            if not isinstance(row['process_state'],str) or len(row['process_state'])!=1:raise ValueError('Invalid process state')
            for key in ('observed_monotonic_s','cpu_percent','interval_s'):
                if row[key] is not None:finite(row[key])
            if row['comparison'] not in {'compared','new_reused_or_uncomparable'}:raise ValueError('Invalid process comparison')
            if row['comparison']=='compared':
                counter(row['cpu_delta_ticks'])
                if row['interval_s'] is None or row['interval_s']<=0 or row['cpu_percent'] is None:
                    raise ValueError('Incomplete process comparison')
                if row['cpu_percent']!=round(100*row['cpu_delta_ticks']/(data['clock_ticks_per_second']*row['interval_s']),2):
                    raise ValueError('Inconsistent process CPU calculation')
            elif row['cpu_percent'] is not None or row['cpu_delta_ticks'] is not None:raise ValueError('Guessed process comparison')
            if row['service'] is not None:validate_service_unit(row['service'])
            if row['reported_cgroup'] is not None and (not isinstance(row['reported_cgroup'],str) or len(row['reported_cgroup'].encode())>1024):
                raise ValueError('Invalid cgroup data')
        else:
            counter(row['mount_id'])
            if row['mount_id']==0 or row['mount_id'] in identities:raise ValueError('Invalid mount identity')
            identities.add(row['mount_id'])
            for key in ('target','root','device','filesystem_type','mount_source','mount_options','super_options'):
                if not isinstance(row[key],str) or len(row[key])>4096:raise ValueError('Invalid mount metadata')
            if type(row['read_only']) is not bool or row['state'] not in {'available','not_probed','unavailable'}:raise ValueError('Invalid mount state')
            if row['state']=='available':
                capacity=row['capacity']
                for key in ('total_bytes','available_bytes','available_inodes'):counter(capacity[key])
                for key in ('user_used_percent','inode_used_percent'):
                    if capacity[key] is not None:
                        finite(capacity[key])
                        if capacity[key]>100:raise ValueError('Invalid filesystem percentage')
                if type(capacity['read_only_flag']) is not bool:raise ValueError('Invalid mount flags')
                from .filesystems import capacity as compute_capacity
                if compute_capacity(SimpleNamespace(**capacity['raw']))!=capacity:raise ValueError('Inconsistent filesystem calculation')
    return data


def attach(data,runner=None,sample_seconds=0.1):
    runner=runner or CommandRunner()
    for kind in ('processes','filesystems'):
        started=datetime.now(timezone.utc).isoformat()
        source={'state':'unavailable','rows':[],'coverage':{},'reason':'source_not_supported',
                'limitations':['This resource source could not be assessed; no zero/healthy result is inferred.']}
        read=getattr(runner,'read_system_resources',None)
        if read is not None:
            result=read(kind,sample_seconds)
            source.update(command_state=result.state,returncode=result.returncode,reason='command_unsuccessful')
            if result.state=='completed' and result.returncode==0:
                try:
                    if len(result.stdout.encode('utf-8'))>1048576:raise ValueError('Resource output limit')
                    parsed=json.loads(result.stdout,object_pairs_hook=unique_object,parse_constant=reject_constant)
                    bounded_structure(parsed);parsed=validate(parsed,kind)
                    source.update(parsed,reason=None)
                except (ValueError,KeyError,TypeError,OverflowError,UnicodeError,RecursionError):source['reason']='unsupported_or_over_limit_output'
        source.update(started_at=started,finished_at=datetime.now(timezone.utc).isoformat())
        data[kind]=source
    data['collected_at']=datetime.now(timezone.utc).isoformat()
