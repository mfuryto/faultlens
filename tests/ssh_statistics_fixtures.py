"""Invented paged SSH history; no host collection or real authentication data."""
import json
from faultlens.commands import Result
from tests.test_ssh_analysis import ssh_record

START=1767225600000000
BOOT='b'*32


def rows(count=3):
    return [ssh_record('Failed password for synthetic-user from 192.0.2.7 port 2222 ssh2',
        realtime=START+index*1000000,monotonic=index*1000000,_BOOT_ID=BOOT,__CURSOR='s=synthetic;i='+str(index)) for index in range(count)]


class Runner:
    def __init__(self,records=None):self.records=rows() if records is None else records;self.calls=[];self.failure=None
    def read_ssh_page(self,since,until,**options):
        self.calls.append((since,until,options))
        if self.failure is not None:return self.failure
        cursor=options['cursor'];start=0
        if cursor is not None:start=next(i+1 for i,row in enumerate(self.records) if row['__CURSOR']==cursor)
        selected=[row for row in self.records[start:] if (since is None or int(row['__REALTIME_TIMESTAMP'])>=since)
            and int(row['__REALTIME_TIMESTAMP'])<=until and (options['boot_id'] is None or row['_BOOT_ID']==options['boot_id'])]
        return Result('completed','\n'.join(json.dumps(row) for row in selected[:200]),0)
