"""Build and qualify .deb lifecycle in disposable pinned Debian/Ubuntu containers."""
import argparse
import json
import shutil
import signal
from pathlib import Path
import re
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from faultlens.commands import _capture
from build_deb import build, digest, source_version

IMAGES={
    'debian-12':'debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc',
    'ubuntu-24.04':'ubuntu@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8',
}


def run(argv,timeout=120,*,success=True):
    result=_capture(['sh','-c','exec \"$@\" 2>&1','faultlens-package-check',*argv],timeout=timeout,limit=4194304)
    if result.state!='completed' or ((result.returncode==0)!=success):
        raise ValueError('Package qualification command failed: '+str(result.state)+' exit '+str(result.returncode)+' '+json.dumps(result.stdout[-2000:],ensure_ascii=True))
    return result.stdout.strip()


def qualify(target,wheelhouse,artifact=None):
    with tempfile.TemporaryDirectory(prefix='faultlens-package-qualification-') as directory:
        root=Path(directory);root.chmod(0o755)
        base=source_version()
        candidate=base+'~rc1' if '~dev' not in base else base+'+test0'
        upgrade_version=base if '~dev' not in base else base+'+test1'
        first=build(wheelhouse,root/'packages',version=candidate,epoch=1795000000)
        second=build(wheelhouse,root/'repeat',version=candidate,epoch=1795000000)
        if digest(first)!=digest(second): raise ValueError('Package build is not reproducible')
        if artifact is None:
            upgrade=build(wheelhouse,root/'packages',version=upgrade_version,epoch=1795000000)
        else:
            actual=run(['dpkg-deb','--field',str(artifact),'Version'])
            if actual!=upgrade_version or artifact.is_symlink(): raise ValueError('Release artifact version mismatch')
            upgrade=root/'packages'/('faultlens_'+upgrade_version+'_all.deb')
            shutil.copyfile(artifact,upgrade);upgrade.chmod(0o644)
        run(['docker','pull',IMAGES[target]],timeout=180)
        fixtures=root/'source'
        for folder in ('scripts','tests'):
            for source in (ROOT/folder).rglob('*.py'):
                if source.is_symlink(): raise ValueError('Unsafe fixture source')
                target_path=fixtures/source.relative_to(ROOT)
                target_path.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source,target_path)
        shutil.copyfile(ROOT/'requirements-tui.txt',fixtures/'requirements-tui.txt')
        for path in [fixtures,*fixtures.rglob('*')]: path.chmod(0o755 if path.is_dir() else 0o644)
        cidfile=root/'container-id'
        cid=None
        try:
            run(['docker','run','-d','--cidfile',str(cidfile),'--rm','--pull=never',
                 '--cap-drop','ALL','--cap-add','CHOWN','--cap-add','DAC_OVERRIDE',
                 '--cap-add','FOWNER','--cap-add','SETUID','--cap-add','SETGID','--security-opt','no-new-privileges','--pids-limit','256',
                 '--memory','768m','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=128m,mode=1777',
                 '--volume',str(root/'packages')+':/packages:ro',
                 '--volume',str(fixtures)+':/source:ro',
                 '--volume',str(ROOT/'scripts/installed_package_check.py')+':/checks/installed_package_check.py:ro',
                 IMAGES[target],'sleep','900'])
            candidate=cidfile.read_text().strip()
            if not re.fullmatch(r'[0-9a-f]{64}',candidate): raise ValueError('Invalid owned container ID')
            cid=candidate
            release=run(['docker','exec',cid,'cat','/etc/os-release'])
            fields={}
            for line in release.splitlines():
                match=re.fullmatch(r'(ID|VERSION_ID)=\"?([a-z0-9.]+)\"?',line)
                if match: fields[match[1]]=match[2]
            expected=('debian','12') if target=='debian-12' else ('ubuntu','24.04')
            if (fields.get('ID'),fields.get('VERSION_ID'))!=expected: raise ValueError('Pinned target identity mismatch')
            run(['docker','exec',cid,'sh','-ec','test ! -e /usr/bin/python3; test ! -e /usr/bin/faultlens'])
            apt=['docker','exec',cid,'apt-get']
            run([*apt,'--no-download','--no-install-recommends','-y','install','/packages/'+first.name],success=False)
            run(['docker','exec',cid,'sh','-ec','test ! -e /usr/bin/faultlens'])
            run([*apt,'update'],timeout=180)
            run([*apt,'--no-install-recommends','-y','install','/packages/'+first.name],timeout=180)
            # Qualification-only tools exercise real ip/ss formats; package dependencies remain independent.
            run([*apt,'--no-install-recommends','-y','install','iproute2','iptables','nftables'],timeout=180)
            run(['docker','network','disconnect','bridge',cid])
            check=['docker','exec','--user','65534:65534','--env','HOME=/tmp/faultlens-package-operator',
                   '--env','XDG_CONFIG_HOME=/tmp/faultlens-package-operator/.config',
                   '--env','TERM=xterm-256color',cid,'/usr/bin/python3','-I','-B','/checks/installed_package_check.py']
            installed=run([*check,'installed'])
            run([*apt,'--no-install-recommends','-y','install','/packages/'+upgrade.name])
            run([*check,'upgraded'])
            run([*apt,'--no-download','-y','purge','faultlens'])
            run([*check,'removed'])
            print(json.dumps({'target':target,'reproducible_sha256':digest(first),
                'checks':['missing_dependency_offline_failure','apt_dependency_resolution','non_root_installed_cli_tui',
                          'offline_upgrade','purge_preserves_user_files'],
                'installed_checks':installed.splitlines(),'application_network':'disconnected','field_follow_up':'owner_plans_additional_ubuntu_test'}))
        finally:
            if cid is None and cidfile.exists():
                candidate=cidfile.read_text().strip()
                if re.fullmatch(r'[0-9a-f]{64}',candidate):cid=candidate
            if cid is not None:
                _capture(['docker','rm','-f',cid],timeout=30,limit=65536)


def main():
    def interrupted(signum,frame): raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',choices=IMAGES,required=True)
    parser.add_argument('--wheelhouse',type=Path,required=True)
    parser.add_argument('--artifact',type=Path)
    args=parser.parse_args()
    qualify(args.target,args.wheelhouse,args.artifact)


if __name__=='__main__':
    main()
