"""Private bounded reader for two fixed Fail2ban log tails; never arbitrary paths."""
import hashlib
import errno
import json
import os
import stat
import sys

LIMIT=32768


def read(previous=False):
    descriptors=[]
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);descriptors.append(parent)
        for part in ('var','log'):
            parent=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);descriptors.append(parent)
            meta=os.fstat(parent)
            if meta.st_uid!=0 or meta.st_mode&0o002:raise ValueError('Untrusted log directory')
        name='fail2ban.log.1' if previous else 'fail2ban.log'
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);descriptors.append(fd)
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022 or before.st_nlink!=1:raise ValueError('Untrusted log file')
        start=max(0,before.st_size-LIMIT);os.lseek(fd,start,os.SEEK_SET);raw=os.read(fd,LIMIT)
        if start:raw=raw.partition(b'\n')[2]
        after=os.fstat(fd)
        return {'path':'/var/log/'+name,'content':raw.decode('utf-8','strict'),
            'tail_omitted_prefix':start>0,'sha256':hashlib.sha256(raw).hexdigest(),
            'changed_during_read':(before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns),
            'bytes_read':len(raw)}
    finally:
        for fd in reversed(descriptors):os.close(fd)


def main():
    if sys.argv[1:] not in (['current'],['previous']):return 2
    try:value=read(sys.argv[1]=='previous')
    except FileNotFoundError:value={'reader_state':'file_missing'}
    except PermissionError:value={'reader_state':'file_access_denied'}
    except UnicodeError:value={'reader_state':'unsupported_encoding'}
    except ValueError:value={'reader_state':'unsafe_file'}
    except OSError as error:value={'reader_state':'unsafe_file' if error.errno in {errno.ELOOP,errno.ENOTDIR} else 'file_unavailable'}
    print(json.dumps(value,ensure_ascii=True));return 0


if __name__=='__main__':sys.exit(main())
