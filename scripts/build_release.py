"""Build a verified .deb/source/checksum bundle from one clean committed revision."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from build_deb import locked_wheels, wheel_bytes, digest


def git(*args):
    return subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT),*args],timeout=30,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1'})


def safe_path(name):
    value=PurePosixPath(name)
    if value.is_absolute() or '..' in value.parts or not value.parts or '\\' in name:
        raise ValueError('Unsafe source archive path')
    return value


def extract_source(archive,destination):
    with tarfile.open(archive,'r:gz') as handle:
        entries=handle.getmembers()
        if sum(item.size for item in entries)>134217728: raise ValueError('Source archive size limit')
        names=set()
        for item in entries:
            if item.name in names: raise ValueError('Duplicate source archive entry')
            names.add(item.name)
            relative=safe_path(item.name)
            target=destination/relative
            if not target.resolve().is_relative_to(destination.resolve()): raise ValueError('Source path escapes destination')
            if item.isdir(): target.mkdir(parents=True,exist_ok=True)
            elif item.isfile():
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(handle.extractfile(item).read())
                target.chmod(0o755 if item.mode & 0o111 else 0o644)
            else: raise ValueError('Non-regular source archive entry')


def verify_audit(source,version):
    lock=(source/'requirements-tui.txt').read_bytes()
    report=json.loads((source/('docs/security/dependency-audit-'+version+'.json')).read_text())
    if report['requirements_sha256']!=hashlib.sha256(lock).hexdigest():
        raise ValueError('Advisory audit does not match dependency inputs')
    expected={}
    for line in lock.decode().splitlines():
        if line and not line.startswith('#'):
            name,version=line.split(' --hash=',1)[0].split('==')
            expected[re.sub(r'[-_.]+','-',name.lower())]=version
    dependencies=report['results']['dependencies']
    observed={re.sub(r'[-_.]+','-',item['name'].lower()):item.get('version') for item in dependencies}
    if observed!=expected or len(dependencies)!=len(expected) or any(not isinstance(item.get('vulns'),list) or item['vulns'] or 'skip_reason' in item for item in dependencies):
        raise ValueError('Dependency audit has findings, skips or incomplete coverage')
    return {'checked_at':report['checked_at'],'tool':report['tool'],'dependencies':len(dependencies)}


def bundle(wheelhouse,output,ref='HEAD'):
    if output.exists() or output.is_symlink(): raise ValueError('Release output already exists')
    if git('status','--porcelain','--untracked-files=normal').strip():
        raise ValueError('Release preparation requires a clean checkout')
    commit=git('rev-parse','--verify','--end-of-options',ref+'^{commit}').decode().strip()
    if re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',commit) is None: raise ValueError('Invalid commit identity')
    epoch=int(git('show','-s','--format=%ct',commit))
    raw=git('archive','--format=tar',commit)
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.faultlens-release-',dir=output.parent) as directory:
        temporary=Path(directory);source=temporary/'source';source.mkdir()
        members={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as handle:
            for item in handle.getmembers():
                path=safe_path(item.name)
                if item.isdir(): continue
                if not item.isfile(): raise ValueError('Release source must contain regular files only')
                data=handle.extractfile(item).read()
                members[str(path)]=(data,0o755 if item.mode & 0o111 else 0o644)
                target=source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        match=re.search(r'__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"',(source/'faultlens/__init__.py').read_text())
        if match is None: raise ValueError('Release version must be stable semantic version')
        version=match[1];audit=verify_audit(source,version)
        # Resolve and verify locks from the exported revision, never the mutable checkout.
        import build_deb
        previous=build_deb.ROOT
        try:
            build_deb.ROOT=source
            wheels=locked_wheels(wheelhouse)
        finally: build_deb.ROOT=previous
        frozen=temporary/'wheels';frozen.mkdir()
        for path,pin in wheels:
            data=wheel_bytes(path)
            if hashlib.sha256(data).hexdigest()!=pin['sha256']: raise ValueError('Wheel changed before source freeze')
            (frozen/path.name).write_bytes(data)
            members['vendor-wheels/'+path.name]=(data,0o644)
        metadata={'schema_version':1,'version':version,'git_commit':commit,'source_date_epoch':epoch,'dependency_audit':audit}
        command=('python3 scripts/build_deb.py --wheelhouse vendor-wheels --output-dir dist '
                 '--version '+version+' --epoch '+str(epoch)+' --source-revision '+commit+'\n')
        if 'REBUILD.txt' in members or 'release-input.json' in members: raise ValueError('Reserved release input path')
        members['REBUILD.txt']=(('Rebuild from this directory with Python 3.11+ and dpkg-deb. No network or pip is needed.\n'+command).encode(),0o644)
        members['release-input.json']=((json.dumps(metadata,sort_keys=True,indent=2)+'\n').encode(),0o644)
        assets=temporary/'assets';assets.mkdir()
        archive=assets/('faultlens-'+version+'-source.tar.gz')
        with archive.open('wb') as destination:
            with gzip.GzipFile(filename='',mode='wb',fileobj=destination,mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as tar:
                    for name,(data,mode) in sorted(members.items()):
                        item=tarfile.TarInfo('faultlens-'+version+'/'+name)
                        item.size=len(data);item.mode=mode;item.mtime=epoch;item.uid=item.gid=0
                        tar.addfile(item,io.BytesIO(data))
        def build_at(root,destination,wheels_path):
            subprocess.run([sys.executable,'-I','-B',str(root/'scripts/build_deb.py'),
                            '--wheelhouse',str(wheels_path),'--output-dir',str(destination),
                            '--version',version,'--epoch',str(epoch),'--source-revision',commit],check=True,timeout=120)
            return destination/('faultlens_'+version+'_all.deb')
        package=build_at(source,assets,frozen)
        restored=temporary/'restored';restored.mkdir();extract_source(archive,restored)
        restored=restored/('faultlens-'+version)
        rebuilt=build_at(restored,temporary/'rebuilt',restored/'vendor-wheels')
        if digest(package)!=digest(rebuilt): raise ValueError('Source bundle does not reproduce package bytes')
        metadata.update(source_rebuild_verified=True,artifacts={path.name:digest(path) for path in (package,archive)})
        (assets/'release.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
        (assets/'SHA256SUMS').write_text(''.join(digest(path)+'  '+path.name+'\n' for path in sorted(assets.iterdir())))
        assets.rename(output)
    return metadata


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheelhouse',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--ref',default='HEAD')
    args=parser.parse_args()
    result=bundle(args.wheelhouse.resolve(),args.output_dir.resolve(),args.ref)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__': main()
