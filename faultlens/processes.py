"""Bounded procfs process sampling; PID/start identity and observation time stay explicit."""
import heapq
import os
import re
import stat
import time
import errno

from .commands import validate_service_unit

MAX_PROCESSES=512
MAX_ENTRIES=32768
DIRECTORY=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK


def read_at(directory,name,limit):
    descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):raise ValueError('Nonregular proc source')
        data=os.read(descriptor,limit+1)
        if len(data)>limit:raise ValueError('Proc source size limit')
        return data.decode('utf-8',errors='strict')
    finally:os.close(descriptor)


def natural(value):
    if not isinstance(value,str) or re.fullmatch('[0-9]{1,20}',value) is None or int(value)>2**64-1:
        raise ValueError('Unsupported process counter')
    return int(value)


def parse_stat(text,pid,page_size):
    prefix=str(pid)+' ('
    end=text.rfind(') ')
    if not text.startswith(prefix) or end<len(prefix) or len(text.encode('utf-8'))>4096:
        raise ValueError('Unsupported process stat identity')
    name=text[len(prefix):end];fields=text[end+2:].split()
    if not name or len(name)>256 or not 22<=len(fields)<=128 or re.fullmatch('[A-Za-z]',fields[0]) is None:
        raise ValueError('Unsupported process stat fields')
    cpu=natural(fields[11])+natural(fields[12]);rss=natural(fields[21])*page_size
    if cpu>2**64-1 or rss>2**64-1:raise ValueError('Process capacity range')
    return {'pid':pid,'name':name,'process_state':fields[0],'cpu_ticks':cpu,
            'start_ticks':natural(fields[19]),'rss_bytes':rss,'virtual_bytes':natural(fields[20])}


def system_service(text):
    candidates=set()
    for line in text.splitlines():
        fields=line.split(':',2)
        if len(fields)!=3:raise ValueError('Unsupported cgroup row')
        hierarchy,controllers,path=fields
        if hierarchy!='0' and 'name=systemd' not in controllers.split(','):continue
        parts=path.split('/')
        if len(parts)>2 and parts[0]=='' and parts[1]=='system.slice':
            for part in reversed(parts[2:]):
                if part.endswith('.service'):
                    try:candidates.add(validate_service_unit(part))
                    except ValueError:pass
                    break
    return next(iter(candidates)) if len(candidates)==1 else None


def snapshot(directory,page_size,clock=time.monotonic):
    names=[];enumeration_limited=False
    with os.scandir(directory) as entries:
        for index,entry in enumerate(entries):
            if index>=MAX_ENTRIES:enumeration_limited=True;break
            if entry.name.isascii() and entry.name.isdecimal() and 0<int(entry.name)<2**31:
                names.append(int(entry.name))
    chosen=heapq.nsmallest(MAX_PROCESSES,names);rows=[];errors=0;cgroup_errors=0
    kinds={'vanished':0,'access_denied':0,'unsupported':0,'other_io':0}
    for pid in chosen:
        descriptor=None
        try:
            descriptor=os.open(str(pid),DIRECTORY,dir_fd=directory)
            row=parse_stat(read_at(descriptor,'stat',4096),pid,page_size)
            row['observed_monotonic_s']=clock()
            try:
                text=read_at(descriptor,'cgroup',1024)
                row.update(service=system_service(text),reported_cgroup=text,cgroup_state='available')
            except (OSError,ValueError,UnicodeError):
                cgroup_errors+=1;row.update(service=None,reported_cgroup=None,cgroup_state='unavailable')
            rows.append(row)
        except OSError as error:
            errors+=1
            kind='vanished' if error.errno in {errno.ENOENT,errno.ESRCH} else 'access_denied' if error.errno in {errno.EACCES,errno.EPERM} else 'other_io'
            kinds[kind]+=1
        except (ValueError,UnicodeError):errors+=1;kinds['unsupported']+=1
        finally:
            if descriptor is not None:os.close(descriptor)
    return {'rows':rows,'visible_numeric_entries':len(names),'read_errors':errors,'errors_by_kind':kinds,'cgroup_errors':cgroup_errors,
            'process_limit_reached':len(names)>MAX_PROCESSES,'enumeration_limit_reached':enumeration_limited}


def compare(before,after,hz):
    previous={row['pid']:row for row in before['rows']};rows=[]
    for row in after['rows']:
        value=dict(row);old=previous.get(row['pid']);elapsed=None;cpu=None
        if old is not None and old['start_ticks']==row['start_ticks']:
            elapsed=row['observed_monotonic_s']-old['observed_monotonic_s']
            delta=row['cpu_ticks']-old['cpu_ticks']
            if elapsed>0 and delta>=0:cpu=round(100*delta/(hz*elapsed),2)
        value.update(cpu_percent=cpu,cpu_delta_ticks=delta if cpu is not None else None,
                     interval_s=elapsed if elapsed is not None and elapsed>0 else None,
                     comparison='compared' if cpu is not None else 'new_reused_or_uncomparable')
        rows.append(value)
    return rows


def collect(sample_seconds):
    page_size=os.sysconf('SC_PAGE_SIZE');hz=os.sysconf('SC_CLK_TCK')
    if not 0<page_size<=16777216 or not 0<hz<=1000000:raise ValueError('Unsupported kernel sampling units')
    directory=os.open('/proc',DIRECTORY)
    try:
        before=snapshot(directory,page_size);time.sleep(sample_seconds);after=snapshot(directory,page_size)
    finally:os.close(directory)
    rows=compare(before,after,hz)
    incomplete=not rows or any(row['cpu_percent'] is None for row in rows) or any(
        source[key] for source in (before,after) for key in
        ('read_errors','cgroup_errors','process_limit_reached','enumeration_limit_reached'))
    return {'schema_version':1,'command':'processes','state':'partial' if incomplete else 'available','rows':rows,
            'clock_ticks_per_second':hz,'page_size':page_size,'requested_sample_seconds':sample_seconds,
            'coverage':{'before':{k:v for k,v in before.items() if k!='rows'},
                        'after':{k:v for k,v in after.items() if k!='rows'},
                        'uncomparable_rows':sum(row['cpu_percent'] is None for row in rows)},
            'limitations':['Current PID namespace and existing access only; at most 512 lowest visible PIDs per sample.',
                'CPU is a short per-process interval relative to one logical CPU; multithreaded processes can exceed 100%.',
                'PID plus reported start ticks must agree; exits, reuse, counter regressions and restricted access leave gaps.',
                'RSS is a current approximate resident snapshot, not private memory, PSS, cgroup headroom or evidence of past pressure.',
                'Shared resident pages can appear in multiple processes; do not sum RSS as unique host memory.',
                'Names can be truncated by the kernel. Command lines, environments and process file descriptors are not collected.',
                'Cgroup paths provide a reported system-service association only; process moves and sequential reads are not atomic.']}
