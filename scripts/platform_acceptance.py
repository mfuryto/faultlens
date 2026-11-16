"""Qualify fixed Linux process environments; never claim full server acceptance."""
import argparse
from importlib.metadata import PackageNotFoundError,version
import json
import os
import platform
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from faultlens.commands import _capture

IMAGE='python@sha256:726d304906fa5eb468e5531e366548d1903286352f5adb54ef508ac01fbd80c6'
WHEELS=Path('/tmp/faultlens-platform-wheels')
TARGETS={'debian-12':('debian','12',(3,11)),'ubuntu-24.04':('ubuntu','24.04',(3,12))}
CONTAINER_SCRIPT='''python -I -B scripts/platform_acceptance.py --target debian-12
python -m venv /tmp/faultlens-ui-env
/tmp/faultlens-ui-env/bin/python -m pip install --disable-pip-version-check --no-index --find-links=/wheels --require-hashes --only-binary=:all: -r requirements-tui.txt
/tmp/faultlens-ui-env/bin/python -m unittest discover -s tests -q 2>&1
/tmp/faultlens-ui-env/bin/python -I -B scripts/platform_acceptance.py --target debian-12 --frontend
'''


def release():
    with open('/etc/os-release','rb') as handle: raw=handle.read(8193)
    if len(raw)>8192: raise ValueError('OS metadata exceeds limit')
    result={}
    for line in raw.decode('utf-8').splitlines():
        if line.startswith(('ID=','VERSION_ID=')):
            match=re.fullmatch(r'(ID|VERSION_ID)=(?:"([a-z0-9._-]{1,32})"|([a-z0-9._-]{1,32}))',line)
            if match is None or match[1] in result: raise ValueError('Unsupported OS metadata')
            result[match[1]]=match[2] or match[3]
    return result


def frontend_version():
    try:return version('textual')
    except PackageNotFoundError:return None


def native(target,*,frontend=False,execute=_capture,os_info=release,ui_version=frontend_version,python=sys.version_info,architecture=platform.machine()):
    expected=TARGETS[target];observed=os_info()
    if architecture!='x86_64': raise ValueError('Qualification target requires Linux x86-64')
    if (observed.get('ID'),observed.get('VERSION_ID'),tuple(python[:2]))!=expected:
        raise ValueError('Process environment does not match the selected qualification target')
    ui=ui_version()
    if ui!=('8.2.8' if frontend else None): raise ValueError('Optional frontend does not match the expected reviewed/absent setup')
    checks=[]
    commands=(('status',),('health',),('network','--sockets'),('history','--system-journal'),
              ('diagnose','--boot','0','--system-journal','--search-events'))
    for options in commands:
        result=execute([sys.executable,'-I','-B',str(ROOT/'bin/faultlens'),*options,'--json'],timeout=30,limit=4194304)
        if result.state!='completed' or result.returncode!=0: raise ValueError('Native CLI contract did not complete: '+options[0])
        try:data=json.loads(result.stdout)
        except (ValueError,RecursionError) as exc: raise ValueError('Native CLI returned invalid JSON: '+options[0]) from exc
        if not isinstance(data,dict) or data.get('schema_version')!=1 or data.get('command')!=options[0]:
            raise ValueError('Native CLI returned an unexpected report: '+options[0])
        if options[0] in {'status','health'}:
            values={item['key']:item for item in data.get('observations',[])}
            if not any(values.get(key,{}).get('value') is not None for key in ('cpu.busy','memory.used')):
                raise ValueError('Native resource measurements were not available: '+options[0])
        if options[0]=='health' and data.get('failed_services',{}).get('state') not in {'available','unavailable'}:
            raise ValueError('Native failed-service source state was not reported')
        if options[0]=='network' and (data.get('state') not in {'available','partial'} or data.get('sockets',{}).get('state') not in {'available','unavailable'}):
            raise ValueError('Native network/socket source states were not reported')
        if options[0] in {'history','diagnose'} and data.get('state') not in {'available','unavailable'}:
            raise ValueError('Native journal source state was not reported')
        if options[0]=='diagnose' and data.get('state')=='unavailable':
            readable=execute([sys.executable,'-I','-B',str(ROOT/'bin/faultlens'),*options],timeout=30,limit=4194304)
            if readable.state!='completed' or readable.returncode!=0 or 'could not be assessed' not in readable.stdout or any(
                    phrase in readable.stdout for phrase in ('No supported journal pattern matched','No supported fault pattern matched')):
                raise ValueError('Unavailable native journal was not explained as unassessed')
        checks.append({'command':options[0],'contract':'PASS','source_state':data.get('state','observations')})
    return {'target':target,'scope':'Native process contracts only; not booted-server or SSH acceptance.',
            'python':'.'.join(str(value) for value in python[:3]),'frontend':'reviewed' if frontend else 'absent',
            'checks':checks,'operator_acceptance':'pending'}


def container_argv(cidfile,uid=None,gid=None):
    uid=os.geteuid() if uid is None else uid;gid=os.getegid() if gid is None else gid
    if type(uid) is not int or type(gid) is not int or uid<=0 or gid<0: raise ValueError('Run platform qualification as a non-root checkout owner')
    return ['docker','run','--cidfile',str(cidfile),'--rm','--pull=never','--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--pids-limit','128','--memory','512m','--cpus','1',
            '--user',str(uid)+':'+str(gid),'--tmpfs','/tmp:rw,nosuid,nodev,size=256m,mode=1777',
            '--volume',str(ROOT)+':/workspace:ro','--volume',str(WHEELS)+':/wheels:ro',
            '--workdir','/workspace',IMAGE,'sh','-ec',CONTAINER_SCRIPT]


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',choices=TARGETS,required=True)
    parser.add_argument('--frontend',action='store_true',help='Require the reviewed optional frontend; otherwise require its absence.')
    parser.add_argument('--container',action='store_true',help='Run the fixed isolated Debian qualification using explicitly prepared wheels/image.')
    args=parser.parse_args(argv)
    if args.container and (args.target!='debian-12' or args.frontend): parser.error('Container mode selects the fixed Debian absent/reviewed test sequence.')
    try:
        if args.container:
            if not WHEELS.is_dir(): raise ValueError('Prepare the reviewed wheels in /tmp/faultlens-platform-wheels first')
            with tempfile.TemporaryDirectory(prefix='faultlens-platform-') as folder:
                cidfile=Path(folder)/'container-id'
                try:
                    result=_capture(container_argv(cidfile),timeout=240,limit=262144)
                    if result.state!='completed' or result.returncode!=0: raise ValueError('Isolated Debian qualification failed; inspect locally without uploading native evidence')
                    print(result.stdout,end='')
                finally:
                    if cidfile.exists():
                        identity=cidfile.read_text().strip()
                        if re.fullmatch('[a-f0-9]{64}',identity): _capture(['docker','rm','--force',identity],timeout=10,limit=4096)
        else: print(json.dumps(native(args.target,frontend=args.frontend),ensure_ascii=True))
        return 0
    except KeyboardInterrupt:
        print('Platform qualification interrupted; no server configuration was changed.',file=sys.stderr);return 130
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print('Platform qualification failed: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
