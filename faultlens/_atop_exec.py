"""Internal isolated child: constrain only this process before executing Atop."""
import ctypes
from datetime import datetime
import os
import resource
import sys


ENVIRONMENT = {'PATH': '/usr/bin:/usr/sbin:/bin:/sbin', 'LANG': 'C', 'LC_ALL': 'C',
               'HOME': '/nonexistent', 'TZ': 'UTC', 'PAGER': '', 'SYSTEMD_PAGER': ''}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) not in {4, 5} or (len(args) == 5 and args[4] != 'extended'):
        return 125
    extended = len(args) == 5
    executable, descriptor, start, end = args[:4]
    # Select a fixed executable value, never use a caller-supplied program path.
    executable = {path: path for path in ('/usr/bin/atop', '/usr/sbin/atop', '/bin/atop', '/sbin/atop')}.get(executable)
    if executable is None:
        return 125
    try:
        if not descriptor.isascii() or not descriptor.isdecimal() or int(descriptor) < 3:
            return 125
        for value in (start, end):
            if len(value) != 14 or not value.isascii() or not value.isdecimal():
                return 125
            datetime.strptime(value, '%Y%m%d%H%M%S')
        if start > end:
            return 125
        # PR_SET_NO_NEW_PRIVS: native file capabilities or set-id bits cannot elevate.
        if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
            return 125
        for kind, value in ((resource.RLIMIT_AS, 64 * 1024 * 1024),
                            (resource.RLIMIT_CPU, 2), (resource.RLIMIT_FSIZE, 0),
                            (resource.RLIMIT_CORE, 0)):
            resource.setrlimit(kind, (value, value))
        os.set_inheritable(int(descriptor), True)
        # Atop 2.12.1 treats -e as an explicit screen-output flag too. The parent
        # stops at a validated SEP boundary instead; never request a screen handler.
        labels = 'CPU,MEM,SWP,DSK,NET,PRC,PRM' if extended else 'CPU,MEM,SWP'
        os.execve(executable, [executable, '-r', '/proc/self/fd/' + descriptor,
                             '-P', labels, '-b', start] + (['-Z'] if extended else []), ENVIRONMENT)
    except (OSError, ValueError):
        return 125
    return 125


if __name__ == '__main__':
    raise SystemExit(main())
