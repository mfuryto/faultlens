"""Build an offline, reproducible pre-release .deb from reviewed pure-Python wheels."""
import argparse
import io
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_WHEEL = 16 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wheel_bytes(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as handle:
        info=os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_WHEEL:
            raise ValueError('Unsafe wheel input')
        data=handle.read(MAX_WHEEL+1)
    if len(data)>MAX_WHEEL: raise ValueError('Wheel size limit')
    return data


def locked_wheels(wheelhouse):
    expected = {}
    for line in (ROOT/'requirements-tui.txt').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([0-9.]+) --hash=sha256:([0-9a-f]{64})', line)
        if match is None or match[3] in expected:
            raise ValueError('Unsupported or duplicate dependency pin')
        expected[match[3]] = {'name': match[1], 'version': match[2], 'sha256': match[3]}
    wheels = []
    for path in sorted(wheelhouse.glob('*.whl')):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_WHEEL:
            raise ValueError('Unsafe wheel input')
        value = hashlib.sha256(wheel_bytes(path)).hexdigest()
        if value not in expected:
            raise ValueError('Wheel not present in reviewed hash lock')
        wheels.append((path, expected.pop(value)))
    if expected or not wheels:
        raise ValueError('Incomplete reviewed wheel closure')
    return wheels


def unpack_wheel(path, destination, expected_sha256=None):
    """Bundle the exact purelib tree; never execute wheels or generate entry points."""
    raw=wheel_bytes(path)
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest()!=expected_sha256:
        raise ValueError('Wheel changed after lock validation')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) > 12000 or sum(item.file_size for item in entries) > MAX_EXPANDED:
            raise ValueError('Wheel expansion limit')
        tags = [item for item in entries if item.filename.endswith('.dist-info/WHEEL')]
        if len(tags) != 1 or 'Root-Is-Purelib: true' not in archive.read(tags[0]).decode().splitlines() or [line for line in archive.read(tags[0]).decode().splitlines() if line.startswith('Tag:')] != ['Tag: py3-none-any']:
            raise ValueError('Only reviewed universal pure-Python wheels are supported')
        names = set()
        for item in entries:
            name = PurePosixPath(item.filename)
            if (name.is_absolute() or '..' in name.parts or '\\' in item.filename or
                    not name.parts or any(part.endswith('.data') for part in name.parts) or
                    stat.S_ISLNK(item.external_attr >> 16) or item.filename in names):
                raise ValueError('Unsafe wheel layout')
            names.add(item.filename)
            if item.is_dir():
                continue
            target = destination / name
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError('Wheel path escapes private payload')
            if target.exists():
                raise ValueError('Overlapping wheel payload')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(item))


def application_files():
    entries=(ROOT/'packaging/debian/application-files.txt').read_text().splitlines()
    if not entries or len(entries)>512 or len(entries)!=len(set(entries)) or any(
            re.fullmatch(r'faultlens/[A-Za-z0-9_]+\.py',name) is None for name in entries):
        raise ValueError('Unsafe application source allowlist')
    return [ROOT/name for name in sorted(entries)]


def source_version():
    match = re.search(r'__version__ = "([0-9]+\.[0-9]+\.[0-9]+)\.dev([0-9]+)"', (ROOT/'faultlens/__init__.py').read_text())
    if match is None:
        raise ValueError('Review package version mapping before a release build')
    return match[1]+'~dev'+match[2]


def build(wheelhouse, output, *, version=None, epoch=None):
    base = source_version()
    snapshot=None
    if epoch is None or version is None:
        value=subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT),'log','-1','--format=%ct:%H'],text=True,timeout=5).strip()
        if not re.fullmatch(r'[0-9]+:(?:[0-9a-f]{40}|[0-9a-f]{64})',value):
            raise ValueError('Unable to determine snapshot identity')
        timestamp,snapshot=value.split(':')
    version = version or (base+'+git'+timestamp+'.'+snapshot[:12])
    if not re.fullmatch(re.escape(base)+r'(?:\+[a-z0-9][a-z0-9.+~]*)?', version):
        raise ValueError('Package version must retain the current pre-release identity')
    if epoch is None:
        epoch = int(timestamp)
    if type(epoch) is not int or not 0 <= epoch <= 2147483647:
        raise ValueError('Invalid reproducible build epoch')
    wheels = locked_wheels(wheelhouse)
    output.mkdir(parents=True, exist_ok=True)
    result = output / ('faultlens_'+version+'_all.deb')
    if result.exists() or result.is_symlink():
        raise ValueError('Refusing to overwrite an existing artifact')
    with tempfile.TemporaryDirectory(prefix='.faultlens-deb-',dir=output) as directory:
        stage = Path(directory)/'package'
        private = stage/'usr/share/faultlens'
        app = private/'faultlens'
        inputs = {}
        for source in application_files():
            if source.is_symlink():
                raise ValueError('Source symlinks are not package inputs')
            target = app/source.relative_to(ROOT/'faultlens')
            target.parent.mkdir(parents=True, exist_ok=True)
            raw=source.read_bytes();target.write_bytes(raw)
            inputs[str(source.relative_to(ROOT))] = hashlib.sha256(raw).hexdigest()
        for path, pin in wheels:
            unpack_wheel(path, private/'vendor',pin['sha256'])
        launcher = private/'bin/faultlens'
        launcher.parent.mkdir(parents=True)
        launcher_bytes=(ROOT/'packaging/debian/faultlens').read_bytes()
        control_bytes=(ROOT/'packaging/debian/control').read_bytes()
        launcher.write_bytes(launcher_bytes)
        public = stage/'usr/bin/faultlens'
        public.parent.mkdir(parents=True)
        public.symlink_to('/usr/share/faultlens/bin/faultlens')
        docs = stage/'usr/share/doc/faultlens'
        docs.mkdir(parents=True)
        for name, source in (('copyright',ROOT/'NOTICE'),('LICENSE',ROOT/'LICENSE'),
                             ('README.md',ROOT/'README.md'),('third-party.md',ROOT/'docs/third-party.md'),
                             ('requirements-tui.txt',ROOT/'requirements-tui.txt'),
                             ('README.Debian',ROOT/'packaging/debian/README.Debian')):
            raw=source.read_bytes();(docs/name).write_bytes(raw)
            inputs[str(source.relative_to(ROOT))] = hashlib.sha256(raw).hexdigest()
        inputs['packaging/debian/application-files.txt'] = digest(ROOT/'packaging/debian/application-files.txt')
        inputs['scripts/build_deb.py'] = digest(Path(__file__).resolve())
        inputs['packaging/debian/control'] = hashlib.sha256(control_bytes).hexdigest()
        inputs['packaging/debian/faultlens'] = hashlib.sha256(launcher_bytes).hexdigest()
        manifest = {'schema_version':1,'package_version':version,'source_date_epoch':epoch,
                    'source_revision_observed':snapshot,'source_cleanliness':'not_attested; actual input files hashed',
                    'source_sha256':inputs,'wheels':[value for _, value in wheels],
                    'runtime':'system python3 >= 3.11; private reviewed pure-Python closure'}
        (docs/'build-manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n')
        control = stage/'DEBIAN'
        control.mkdir()
        size = sum(path.stat().st_size for path in stage.rglob('*') if path.is_file() and not path.is_symlink())
        (control/'control').write_text(control_bytes.decode().replace('@VERSION@',version).replace('@SIZE@',str((size+1023)//1024)))
        for path in sorted(stage.rglob('*'), reverse=True):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path==launcher else 0o644)
                os.utime(path, (epoch,epoch))
        stage.chmod(0o755);os.utime(stage,(epoch,epoch))
        built=Path(directory)/result.name
        subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zxz','-z6','--build',str(stage),str(built)],
                       check=True, timeout=60, env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch),'LC_ALL':'C'})
        built.chmod(0o644)
        os.link(built,result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheelhouse',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,default=ROOT/'dist')
    parser.add_argument('--version')
    parser.add_argument('--epoch',type=int)
    args=parser.parse_args()
    try:
        result=build(args.wheelhouse,args.output_dir,version=args.version,epoch=args.epoch)
    except (OSError,ValueError,subprocess.SubprocessError,zipfile.BadZipFile) as error:
        parser.exit(1,'Package build failed: '+type(error).__name__+'; inspect build inputs.\n')
    print(str(result)+'\nSHA256 '+digest(result))


if __name__=='__main__':
    main()
