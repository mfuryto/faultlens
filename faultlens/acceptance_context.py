"""Bounded local qualification context, without identities or diagnostic evidence."""
from importlib.metadata import PackageNotFoundError, version
import os
from pathlib import Path
import platform
import re
import stat
import sys

from .commands import _capture

ROOT = Path(__file__).resolve().parents[1]


def os_release():
    try:
        with open('/etc/os-release', 'rb') as handle:
            raw = handle.read(8193)
        if len(raw) > 8192:
            raise ValueError('OS metadata limit')
        values = {}
        for line in raw.decode('utf-8').splitlines():
            if line.startswith(('ID=', 'VERSION_ID=')):
                match = re.fullmatch(r'(ID|VERSION_ID)=(?:"([a-z0-9._-]{1,64})"|([a-z0-9._-]{1,64}))', line)
                if match is None or match[1] in values:
                    raise ValueError('Unsupported OS metadata')
                values[match[1]] = match[2] or match[3]
        return {'id': values.get('ID'), 'version_id': values.get('VERSION_ID')}
    except (OSError, ValueError, UnicodeError):
        return {'id': None, 'version_id': None}


def revision(root=ROOT, *, execute=_capture):
    """Resolve HEAD only: no status hooks, filters, network or Git trust exceptions."""
    try:
        if os.geteuid() == 0 or os.geteuid() != root.stat().st_uid:
            return None
        executable = Path('/usr/bin/git').resolve(strict=True)
        for component in (executable, *executable.parents):
            info = component.stat()
            if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return None
        result = execute([str(executable), '--no-optional-locks', '-C', str(root),
                          'rev-parse', '--verify', 'HEAD'], timeout=2, limit=1024)
        if result.state == 'completed' and result.returncode == 0 and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\n?', result.stdout):
            return result.stdout.strip()
    except (OSError, ValueError, RuntimeError):
        pass
    return None


def collect():
    try:
        frontend = version('textual')
    except (PackageNotFoundError, OSError, ValueError):
        frontend = None
    terminal = {'input_interactive': bool(getattr(sys.stdin, 'isatty', lambda: False)()),
                'output_interactive': bool(getattr(sys.stdout, 'isatty', lambda: False)()), 'columns': None, 'rows': None}
    if terminal['output_interactive']:
        try:
            size = os.get_terminal_size(sys.stdout.fileno())
            if size.columns > 0 and size.lines > 0:
                terminal.update(columns=size.columns, rows=size.lines)
        except (OSError, ValueError):
            pass
    return {'os_release': os_release(), 'python': platform.python_version(),
            'architecture': platform.machine(), 'textual': frontend,
            'checkout_revision': revision(), 'working_tree': 'not_verified',
            'terminal': terminal, 'operator_acceptance': 'not_recorded'}
