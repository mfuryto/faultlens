"""Mount namespace inventory and conservative descriptor-bound local capacity probes."""
import os
from pathlib import PurePosixPath
import re
import stat

from .processes import read_at

MAX_MOUNTS=256
MAX_PROBES=32
LOCAL_TYPES={'ext2','ext3','ext4','xfs','btrfs','f2fs','tmpfs','overlay','squashfs','erofs','zfs'}
SAFE_ANCESTOR_TYPES=LOCAL_TYPES|{'proc','sysfs','devtmpfs','devpts','cgroup','cgroup2','securityfs',
    'pstore','debugfs','tracefs','bpf','mqueue','hugetlbfs','configfs','efivarfs','ramfs'}


def unescape(value):
    replacements={'040':' ','011':'\t','012':'\n','134':'\\'}
    if re.search(r'\\(?!040|011|012|134)',value):raise ValueError('Unsupported mount escape')
    return re.sub(r'\\(040|011|012|134)',lambda match:replacements[match[1]],value)


def mounts(text):
    if len(text.encode('utf-8'))>1048576:raise ValueError('Mount table size limit')
    result=[];seen=set()
    for index,line in enumerate(text.splitlines()):
        if index>=8192:raise ValueError('Mount enumeration limit')
        fields=line.split(' ')
        if '-' not in fields:raise ValueError('Unsupported mount separator')
        separator=fields.index('-')
        if separator<6 or len(fields)!=separator+4:raise ValueError('Unsupported mount row')
        identity,parent,device,root,target,options=fields[:6]
        if (not re.fullmatch('[0-9]{1,20}',identity) or int(identity)==0 or identity in seen
                or not re.fullmatch('[0-9]{1,20}',parent) or not re.fullmatch('[0-9]{1,10}:[0-9]{1,10}',device)):
            raise ValueError('Unsupported mount identity')
        seen.add(identity);root=unescape(root);target=unescape(target)
        # The filesystem root is descriptive (e.g. an anonymous memfd bind root),
        # never an input to path traversal. Only the actual target is opened.
        if not root or '\x00' in root or len(root)>4096:raise ValueError('Unsupported mount root label')
        if not target.startswith('/') or '\x00' in target or '..' in PurePosixPath(target).parts or len(target)>4096:
            raise ValueError('Unsafe reported mount path')
        fs=fields[separator+1]
        if re.fullmatch('[A-Za-z0-9._-]{1,64}',fs) is None:raise ValueError('Unsupported filesystem type')
        result.append({'mount_id':int(identity),'parent_id':int(parent),'device':device,'root':root,
            'target':target,'filesystem_type':fs,'mount_source':unescape(fields[separator+2]),
            'mount_options':options,'super_options':fields[separator+3],
            'read_only':'ro' in options.split(',') or 'ro' in fields[separator+3].split(',')})
    return result


def capacity(data):
    fields=('f_blocks','f_bfree','f_bavail','f_frsize','f_files','f_ffree','f_favail','f_flag')
    raw={name:getattr(data,name) for name in fields}
    if any(type(value) is not int or not 0<=value<=2**64-1 for value in raw.values()):
        raise ValueError('Unsupported filesystem counters')
    if not 0<=raw['f_bavail']<=raw['f_bfree']<=raw['f_blocks'] or raw['f_frsize']==0:
        raise ValueError('Inconsistent filesystem capacity')
    if not 0<=raw['f_favail']<=raw['f_ffree']<=raw['f_files']:raise ValueError('Inconsistent inode capacity')
    if raw['f_blocks']*raw['f_frsize']>2**64-1:raise ValueError('Filesystem byte range')
    used=raw['f_blocks']-raw['f_bfree'];ordinary=used+raw['f_bavail']
    inodes_used=raw['f_files']-raw['f_ffree'];inode_ordinary=inodes_used+raw['f_favail']
    return {'raw':raw,'total_bytes':raw['f_blocks']*raw['f_frsize'],
            'available_bytes':raw['f_bavail']*raw['f_frsize'],
            'user_used_percent':round(100*used/ordinary,2) if ordinary else None,
            'inode_used_percent':round(100*inodes_used/inode_ordinary,2) if inode_ordinary else None,
            'available_inodes':raw['f_favail'],'read_only_flag':bool(data.f_flag & os.ST_RDONLY)}


def probe(row):
    flags=os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    descriptor=os.open('/',flags)
    try:
        parts=PurePosixPath(row['target']).parts[1:]
        for index,part in enumerate(parts):
            selected=flags if index<len(parts)-1 else os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC
            child=os.open(part,selected,dir_fd=descriptor);os.close(descriptor);descriptor=child
        info=os.fstat(descriptor)
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):raise ValueError('Unsupported mount target type')
        expected=tuple(int(part) for part in row['device'].split(':'))
        if (os.major(info.st_dev),os.minor(info.st_dev))!=expected:raise ValueError('Mount device changed')
        fdinfo=os.open('/proc/self/fdinfo',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:metadata=read_at(fdinfo,str(descriptor),4096)
        finally:os.close(fdinfo)
        identities=re.findall(r'^mnt_id:\s+([0-9]+)$',metadata,re.MULTILINE)
        if len(identities)!=1 or int(identities[0])!=row['mount_id']:raise ValueError('Mount identity changed or hidden')
        return capacity(os.fstatvfs(descriptor))
    finally:os.close(descriptor)


def collect_rows(table,measure=probe):
    preferred={'/':0,'/var':1,'/home':2,'/srv':3,'/tmp':4,'/run':5,'/boot':6}
    ordered=sorted(table,key=lambda row:(preferred.get(row['target'],7),len(PurePosixPath(row['target']).parts),row['target'],row['mount_id']))
    retained=ordered[:MAX_MOUNTS];rows=[];probes=errors=limited=0
    unsafe_roots={row['target'] for row in table if row['filesystem_type'] not in SAFE_ANCESTOR_TYPES}
    for row in retained:
        value=dict(row,state='not_probed',capacity=None,reason='filesystem_type_not_probed')
        if row['filesystem_type'] in LOCAL_TYPES:
            unsafe_parent=bool(unsafe_roots & {str(parent) for parent in PurePosixPath(row['target']).parents})
            if unsafe_parent:value['reason']='unprobed_mount_ancestor'
            elif probes>=MAX_PROBES:limited+=1;value['reason']='probe_limit_reached'
            else:
                probes+=1
                try:value.update(state='available',capacity=measure(row),reason=None)
                except (OSError,ValueError,UnicodeError):errors+=1;value.update(state='unavailable',reason='inaccessible_changed_or_unsupported')
        rows.append(value)
    return {'schema_version':1,'command':'filesystems','state':'partial' if errors or limited or len(table)>MAX_MOUNTS else 'available',
            'rows':rows,'coverage':{'mounts_seen':len(table),'mount_limit_reached':len(table)>MAX_MOUNTS,
                'probes_attempted':probes,'probe_limit_reached':bool(limited),'probe_errors':errors,
                'not_probed':sum(row['state']=='not_probed' for row in rows)},
            'limitations':['Current mount namespace and caller access only; at most 256 rows and 32 local capacity probes.',
                'Remote, FUSE, autofs and unsupported types are listed without capacity probes; they are not declared healthy or failed.',
                'Mount ID and device must match the opened descriptor; hidden/changed/inaccessible mounts remain unavailable.',
                'Mounts can share storage. Do not sum their capacities; quotas, bind roots and container limits need separate context.',
                'Available space/inodes describe ordinary-user capacity. Reserved space, permissions and quotas can change actual write access.',
                'A missing inode denominator is unassessed, not inode exhaustion. Read-only mounts may be intentional.',
                'Collection is non-atomic. Local filesystem/kernel I/O can still block; no hard deadline is possible for uninterruptible kernel work.',
                'Capacity and inode counters are not filesystem integrity, hardware health, throughput or historical-pressure evidence.']}


def collect():
    descriptor=os.open('/proc/self',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:table=mounts(read_at(descriptor,'mountinfo',1048576))
    finally:os.close(descriptor)
    return collect_rows(table)
