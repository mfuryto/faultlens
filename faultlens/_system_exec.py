"""Internal read-only resource worker; independent native deadlines apply in the parent."""
import ctypes
import json
from pathlib import Path
import resource
import sys


def main():
    if len(sys.argv)!=3 or sys.argv[1] not in {'processes','filesystems'}:return 125
    try:
        interval=float(sys.argv[2])
        if not 0.05<=interval<=1:return 125
        if ctypes.CDLL(None,use_errno=True).prctl(38,1,0,0,0)!=0:return 125
        for kind,value in ((resource.RLIMIT_AS,128*1024*1024),(resource.RLIMIT_CPU,1),
                           (resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,0),(resource.RLIMIT_NOFILE,64)):
            resource.setrlimit(kind,(value,value))
        sys.dont_write_bytecode=True
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        if sys.argv[1]=='processes':
            from faultlens.processes import collect
            data=collect(interval)
        else:
            from faultlens.filesystems import collect
            data=collect()
        print(json.dumps(data,ensure_ascii=True,allow_nan=False))
        return 0
    except (OSError,ValueError,OverflowError,UnicodeError):return 125


if __name__=='__main__':raise SystemExit(main())
