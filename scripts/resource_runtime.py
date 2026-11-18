"""Private, checked bytecode for synthetic fresh-process resource qualification."""
from contextlib import contextmanager
from importlib import metadata, util
from pathlib import Path
import os
import py_compile
import re
import sys
import sysconfig
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def stdlib_sources(root):
    excluded = {'site-packages', 'dist-packages', 'test', 'tests', '__pycache__', 'ensurepip', 'idlelib', 'tkinter', 'turtledemo'}
    for directory, children, names in os.walk(root):
        children[:] = sorted(name for name in children if name not in excluded)
        for name in sorted(names):
            if name.endswith('.py'):
                yield Path(directory) / name


def source_files():
    """Only this checkout, the interpreter stdlib and the reviewed frontend closure."""
    stdlib = Path(sysconfig.get_path('stdlib'))
    files = set(stdlib_sources(stdlib))
    for directory in ('faultlens', 'scripts', 'tests'):
        files.update((ROOT / directory).rglob('*.py'))
    for line in (ROOT / 'requirements-tui.txt').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([0-9.]+) --hash=sha256:[0-9a-f]{64}', line)
        if match is None:
            raise ValueError('Unsupported resource runtime lock')
        distribution = metadata.distribution(match[1])
        if distribution.version != match[2] or distribution.files is None:
            raise ValueError('Resource runtime differs from reviewed lock')
        files.update(Path(distribution.locate_file(path)) for path in distribution.files if str(path).endswith('.py'))
    return sorted(files)


@contextmanager
def prepared():
    """Prepare once; never write into the checkout or installed interpreter/packages."""
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='faultlens-resource-bytecode-') as directory:
        old_prefix = sys.pycache_prefix
        try:
            sys.pycache_prefix = directory
            for source in source_files():
                py_compile.compile(str(source), cfile=util.cache_from_source(str(source)),
                    doraise=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
        finally:
            sys.pycache_prefix = old_prefix
        yield {'bytecode_cache': 'private_checked_hash',
               'preparation_wall_seconds': round(time.monotonic()-started, 4),
               'interpreter_options': ['-X', 'pycache_prefix='+directory]}
