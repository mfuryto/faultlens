"""Readable current process/filesystem evidence; no process control or storage repair."""
from .presentation import size


def process_errors(snapshot):
    kinds=snapshot.get('errors_by_kind',{})
    if not kinds:return 'Read-error categories not reported'
    labels={'vanished':'exited/disappeared','access_denied':'access denied','unsupported':'unsupported records','other_io':'other read errors'}
    return ', '.join(str(kinds.get(key,0))+' '+label for key,label in labels.items() if kinds.get(key,0)) or 'No classified read errors'


def process_order(source):
    return sorted(source['rows'],key=lambda row:(-(row['cpu_percent'] if row['cpu_percent'] is not None else -1),-row['rss_bytes'],row['pid']))


def process_detail(row,source):
    cpu=(str(row['cpu_percent'])+'% of one logical CPU over '+str(round(row['interval_s'],4))+' s') if row['cpu_percent'] is not None else 'Not comparable; new/reused PID or incomplete interval'
    states={'R':'running','S':'sleeping','D':'uninterruptible wait','Z':'exited, not yet reaped','T':'stopped','t':'tracing stop','I':'idle kernel thread'}
    return {'Observed':'PID '+str(row['pid'])+' | '+row['name']+' | '+states.get(row['process_state'],'unclassified process state '+row['process_state']),
            'CPU sample':cpu,'Resident memory (RSS)':size(row['rss_bytes']),
            'Virtual address space':size(row['virtual_bytes'])+'; not resident memory',
            'Reported service association':row['service'] or 'Not established; inspect original cgroup state',
            'What it means':'Current process evidence only. CPU can exceed 100% for multithreaded work. RSS can include shared pages; it is not unique/private memory or a cgroup limit.',
            'What you can do':['Compare this process with the symptom and repeat the sample. Open the reported system service if available; no process is signaled or stopped.',
                'For an earlier incident, use retained recordings and logs. Current process state does not reconstruct earlier resource pressure.'],
            'Evidence limits':source['limitations']}


def filesystem_assessment(row):
    if row['state']=='not_probed':return 'Info'
    if row['state']!='available':return 'Gap'
    values=row['capacity']
    if row['read_only'] or values['read_only_flag']:return 'Info'
    raw=values['raw'];ratios=[(raw['f_blocks']-raw['f_bfree'],raw['f_blocks']-raw['f_bfree']+raw['f_bavail']),
                            (raw['f_files']-raw['f_ffree'],raw['f_files']-raw['f_ffree']+raw['f_favail'])]
    if any(total>0 and used*100>=total*95 for used,total in ratios):return 'Critical'
    if any(total>0 and used*100>=total*90 for used,total in ratios):return 'Review'
    return 'Measured'


def filesystem_order(source):
    rank={'Critical':0,'Review':1,'Gap':2,'Measured':3,'Info':4}
    return sorted(source['rows'],key=lambda row:(rank[filesystem_assessment(row)],row['target'],row['mount_id']))


def filesystem_detail(row,source):
    values=row['capacity'];state=filesystem_assessment(row)
    if values is None:
        reasons={'filesystem_type_not_probed':'This filesystem type is listed without capacity measurements.',
                 'unprobed_mount_ancestor':'A parent mount is outside the safe probe scope; capacity was not measured.',
                 'probe_limit_reached':'The capacity-probe limit was reached; this mount was not measured.',
                 'inaccessible_changed_or_unsupported':'The mount could not be measured with existing access and identity checks; it may have changed or be unsupported.'}
        observed=reasons.get(row['reason'],'Capacity could not be assessed.')
        measurements=['No capacity or inode values were substituted.']
    else:
        observed=('Read-only status was reported; it may be intentional.' if row['read_only'] or values['read_only_flag'] else
                  'Capacity/inode review threshold reached.' if state in {'Critical','Review'} else 'No configured capacity/inode threshold reached for this sampled mount.')
        measurements=['Size '+size(values['total_bytes'])+'; available to ordinary users '+size(values['available_bytes']),
            'Space used: '+(str(values['user_used_percent'])+'%' if values['user_used_percent'] is not None else 'Not reported; no denominator'),
            'Inodes used: '+(str(values['inode_used_percent'])+'%; '+str(values['available_inodes'])+' available' if values['inode_used_percent'] is not None else 'Not assessed; no inode denominator reported')]
    return {'Observed':row['target']+' | '+row['filesystem_type']+' | '+observed,
            'Measurements':measurements,'What it means':'Capacity/inode evidence for this reported mount only. Mounts can share storage; reserved space, quotas, permissions and container scope affect interpretation. This is not a filesystem or hardware integrity check.',
            'What you can do':['Review the affected mount, file growth, inode use, retention and intended read-only policy before making changes. No files are deleted and no repair is run.',
                'A missing inode denominator or a mount excluded from probing alone does not indicate a fault or require a configuration change.'],
            'View thresholds':'Writable mounts only: review at 90%, critical at 95%, using exact ratios before display rounding.',
            'Evidence limits':source['limitations']}


def decisions(data):
    from .current_views import Decision
    result=[]
    source=data.get('processes')
    if source is not None:
        readable=source['state'] in {'available','partial'};rows=process_order(source)
        compared=[row for row in rows if row['cpu_percent'] is not None]
        value=str(len(rows))+' retained processes' if readable else 'Could not be assessed'
        meaning='Open ranked PID/name/CPU/RSS rows and reported cgroup service associations. These are current bounded samples, not verified causes.'
        if compared:value+='; highest CPU '+str(compared[0]['cpu_percent'])+'% (one CPU)'
        if rows:
            largest=max(rows,key=lambda row:row['rss_bytes'])
            meaning+=' Largest retained RSS: '+largest['name']+' (PID '+str(largest['pid'])+'), '+size(largest['rss_bytes'])+'.'
        result.append(Decision('Processes',value,'Gap' if not rows else 'Partial' if source['state']=='partial' else 'Measured' if readable else 'Gap',meaning,source,
            {'What it means':meaning,'What you can do':['Open processes, compare actual intervals and repeat during the symptom. No process is controlled.'],
             'Sampling coverage':['Retained '+str(len(rows))+' rows; '+str(source['coverage'].get('uncomparable_rows',0))+' CPU comparisons could not be established.',
                 'Before: '+process_errors(source['coverage'].get('before',{}))+'. After: '+process_errors(source['coverage'].get('after',{}))+'. Gaps are not zero usage.',
                 'Any process/enumeration cap limits which PIDs could be examined; all retained rows remain accessible.'],
             'Evidence limits':source['limitations']},'processes'))
    source=data.get('filesystems')
    if source is not None:
        readable=source['state'] in {'available','partial'};rows=filesystem_order(source)
        assessed=sum(row['state']=='available' for row in rows)
        flagged=[row for row in rows if filesystem_assessment(row) in {'Critical','Review'}]
        value=str(assessed)+' mounts sampled; '+str(len(flagged))+' need review' if readable else 'Could not be assessed'
        meaning='Open all retained mounts for space, inode and unprobed-source details. Shared/bind/container mounts must not be summed.'
        meaning+=' '+str(sum(row['state']=='not_probed' for row in rows))+' listed mounts were not capacity-probed.'
        result.append(Decision('Filesystems',value,'Gap' if not assessed else 'Partial' if source['state']=='partial' else 'Measured' if readable else 'Gap',meaning,source,
            {'What it means':meaning,'What you can do':['Inspect the specific affected mount; root filesystem space alone cannot assess separate volumes.'],
             'Evidence limits':source['limitations']},'filesystems'))
        for row in flagged:
            detail=filesystem_detail(row,source);values=row['capacity']
            value='Space '+str(values['user_used_percent'])+'%; inodes '+(str(values['inode_used_percent'])+'%' if values['inode_used_percent'] is not None else 'unassessed')
            result.append(Decision(row['target'],value,filesystem_assessment(row),detail['Observed'],row,detail,'filesystem'))
    return result
