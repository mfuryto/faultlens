"""Invented current process and mount sources; no native host reads."""
from types import SimpleNamespace
from faultlens.processes import parse_stat,compare
from faultlens.filesystems import mounts,collect_rows,capacity


def stat_text(pid=42,name='synthetic-worker',ticks=10,start=100,rss=64):
    fields=['0']*50;fields[0]='S';fields[11]=str(ticks);fields[12]='0'
    fields[19]=str(start);fields[20]='16777216';fields[21]=str(rss)
    return str(pid)+' ('+name+') '+' '.join(fields)+'\n'


def process_report(maximum=False):
    count=512 if maximum else 2
    before=[];after=[]
    for index in range(count):
        pid=index+42
        for collection,observed,ticks in ((before,1.0,10),(after,1.1,11)):
            row=parse_stat(stat_text(pid,'synthetic-worker-'+str(index),ticks=ticks),pid,4096)
            row.update(observed_monotonic_s=observed,service='example-worker.service',
                       reported_cgroup='0::/system.slice/example-worker.service\n',cgroup_state='available')
            collection.append(row)
    return {'schema_version':1,'command':'processes','state':'available','rows':compare({'rows':before},{'rows':after},100),
            'clock_ticks_per_second':100,'page_size':4096,'requested_sample_seconds':0.1,
            'coverage':{'uncomparable_rows':0},'limitations':['Synthetic current process data; no host collection.']}


def fs_values(used=60,inode_used=20,read_only=False):
    return SimpleNamespace(f_blocks=1000,f_bfree=1000-used*10,f_bavail=1000-used*10,
                           f_frsize=4096,f_files=1000,f_ffree=1000-inode_used*10,
                           f_favail=1000-inode_used*10,f_flag=1 if read_only else 0)


def storage_report(maximum=False):
    paths=['/','/var','/run']+(['/srv/synthetic-'+str(index) for index in range(253)] if maximum else [])
    table=mounts('\n'.join(str(index+1)+' 0 8:'+str(index)+' / '+path+' rw - ext4 /dev/synthetic rw' for index,path in enumerate(paths)))
    return collect_rows(table,lambda row:capacity(fs_values()))
