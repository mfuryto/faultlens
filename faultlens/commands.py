"""A fixed read-only command catalog with bounded output and execution time."""
from dataclasses import dataclass
from enum import Enum
import os
import re
from pathlib import Path
import selectors
import signal
import stat
import sys
from datetime import datetime, timezone
import subprocess
import time

from .journal import MAX_REALTIME_US, SHUTDOWN_REQUEST, UNIT_START_FAILED, validate_window


class Command(Enum):
    REFERENCE_MEMORY = "reference_memory"
    REFERENCE_FILESYSTEM = "reference_filesystem"
    SYSTEM_STATE = "system_state"
    FAILED_SERVICES = "failed_services"
    JOURNAL_CONFIG = "journal_config"
    JOURNAL_BOOTS = "journal_boots"
    JOURNAL_SYSTEM_BOOTS = "journal_system_boots"
    JOURNAL_SERVICE = "journal_service"
    ATOP_SERVICE = "atop_service"
    SOCKETS = "sockets"
    SOCKET_OWNERS = "socket_owners"
    NETWORK_ADDRESSES = "network_addresses"
    NETWORK_ROUTES4 = "network_routes4"
    NETWORK_ROUTES6 = "network_routes6"
    LOGIN_SESSIONS = "login_sessions"
    LOGIN_SESSION_LIST = "login_session_list"
    LOGIN_SESSION_SERVICE = "login_session_service"


CATALOG = {
    Command.SOCKET_OWNERS: ("ss", ("-H", "-n", "-O", "-a", "-t", "-u", "-p")),
    Command.NETWORK_ADDRESSES: ("ip", ("-j", "address", "show")),
    Command.NETWORK_ROUTES4: ("ip", ("-j", "-4", "route", "show", "table", "all")),
    Command.NETWORK_ROUTES6: ("ip", ("-j", "-6", "route", "show", "table", "all")),
    Command.LOGIN_SESSIONS: ("who", ("--users",)),
    Command.LOGIN_SESSION_LIST: ("loginctl", ("list-sessions", "--no-legend", "--no-pager", "--no-ask-password")),
    Command.LOGIN_SESSION_SERVICE: ("systemctl", ("is-active", "systemd-logind.service", "--no-pager")),
    Command.FAILED_SERVICES: ("systemctl", ("list-units", "--state=failed", "--type=service", "--all", "--plain", "--no-legend", "--no-pager", "--full")),
    Command.SOCKETS: ("ss", ("-H", "-n", "-O", "-a", "-t", "-u")),
    Command.REFERENCE_MEMORY: ("free", ("--bytes",)),
    Command.REFERENCE_FILESYSTEM: ("df", ("--block-size=1", "--output=size,used,avail,pcent", "/")),
    Command.SYSTEM_STATE: ("systemctl", ("is-system-running", "--no-pager")),
    Command.JOURNAL_CONFIG: ("systemd-analyze", ("cat-config", "systemd/journald.conf")),
    Command.JOURNAL_BOOTS: ("journalctl", ("--list-boots", "--no-pager", "--quiet")),
    Command.JOURNAL_SYSTEM_BOOTS: ("journalctl", ("--system", "--list-boots", "--no-pager", "--quiet")),
    Command.JOURNAL_SERVICE: ("systemctl", ("is-active", "systemd-journald.service", "--no-pager")),
    Command.ATOP_SERVICE: ("systemctl", ("is-active", "atop.service", "--no-pager")),
}
EVENT_FILTERS = {
    'kernel_warnings': ('--priority=warning', '_TRANSPORT=kernel'),
    'systemd_events': ('_PID=1', '_COMM=systemd', 'MESSAGE_ID=' + UNIT_START_FAILED,
                       'MESSAGE_ID=' + SHUTDOWN_REQUEST),
    'ssh_events': ('_UID=0', '_TRANSPORT=syslog', '_COMM=sshd', '_COMM=sshd-session', '_COMM=sshd-auth'),
    'firewall_events': ('_TRANSPORT=kernel',),
}
TOOLS = ("free", "df", "systemctl", "journalctl", "systemd-analyze", "atop", "ss", "who", "loginctl", "ip")
TOOL_PURPOSES = {
    "ip": "Optional: read numeric local addresses/link state and route tables in network context; no route lookup/probe or configuration write.",
    "loginctl": "Optional: inspect existing local logind sessions in System/status; never starts or controls sessions/services.",
    "who": "Optional: reported terminal login sessions in System/status; no DNS lookup or session control.",
    "ss": "Optional: numeric current TCP/UDP endpoints with --sockets, plus permitted reported owners with --network-context.",
    "free": "Optional: memory comparison in scripts/validate_local.py; status reads procfs directly.",
    "df": "Optional: filesystem comparison in scripts/validate_local.py; status uses statvfs directly.",
    "systemctl": "Feature dependency: service observations in status/check; other observations remain available without it.",
    "journalctl": "Feature dependency: visible boot history and journal incident analysis.",
    "systemd-analyze": "Optional: explicit journald configuration in check --history; uses cat-config; availability and output compatibility are checked at collection time.",
    "atop": "Optional: replay only when diagnose --atop-date is requested; historical samples require existing recordings.",
}
DIRECTORIES = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
ENVIRONMENT = {"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "LANG": "C", "LC_ALL": "C",
               "SYSTEMD_PAGER": "", "PAGER": "", "SYSTEMD_COLORS": "0"}
SERVICE_PROPERTIES = ('Id', 'Description', 'LoadState', 'ActiveState', 'SubState',
                      'Result', 'ExecMainCode', 'ExecMainStatus', 'StateChangeTimestamp',
                      'InvocationID', 'FragmentPath')


def validate_service_unit(unit):
    """One literal service name; no options, paths, globs or shell interpretation."""
    atom = r'(?:[A-Za-z0-9_]|\\x[0-9a-fA-F]{2})'
    tail = r'(?:[A-Za-z0-9:_.@-]|\\x[0-9a-fA-F]{2})*'
    if not isinstance(unit, str) or len(unit)>255 or re.fullmatch(atom+tail+r'\.service',unit) is None:
        raise ValueError('Use one literal system service name ending in .service')
    return unit


@dataclass(frozen=True)
class Result:
    state: str
    stdout: str = ""
    returncode: int | None = None


def trusted_tool(name: str) -> str | None:
    if name not in TOOLS:
        raise ValueError("Tool is not in the read-only catalog")
    for directory in DIRECTORIES:
        try:
            path = (Path(directory) / name).resolve(strict=True)
            # Reject executables or ancestors writable by non-root users.
            for component in (path, *path.parents):
                metadata = component.stat()
                if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise ValueError("Untrusted executable location")
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        except (OSError, ValueError, RuntimeError):
            continue
    return None


def _capture(argv: list[str], timeout: float = 2.0, limit: int = 262144, pass_fds=(), end_when=None, graceful=False, utc=False) -> Result:
    """Drain both pipes without communicate's unbounded in-memory buffering."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, env={**ENVIRONMENT,"TZ":"UTC"} if utc else ENVIRONMENT,
                               cwd="/", start_new_session=True, pass_fds=pass_fds)
    output = bytearray()
    total = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return Result("timeout")
                for key, _ in selector.select(min(remaining, 0.05)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > limit:
                        return Result("output_limit")
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
                        if end_when is not None:
                            boundary = end_when(output)
                            if boundary is not None:
                                return Result("window_complete", output[:boundary].decode("utf-8", errors="strict"))
            return Result("completed", output.decode("utf-8", errors="strict"), process.returncode)
    finally:
        # Give nested acceptance workers a chance to clean their own isolated children.
        if graceful and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGINT)
                process.wait(timeout=1)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        # Also kill descendants retaining pipes after the direct child exits.
        try:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1)
        finally:
            process.stdout.close()
            process.stderr.close()


class CommandRunner:
    def read_system_resources(self,kind,sample_seconds):
        import math
        if (not isinstance(kind,str) or kind not in {'processes','filesystems'} or type(sample_seconds) not in {int,float}
                or not math.isfinite(sample_seconds) or not 0.05<=sample_seconds<=1):
            raise ValueError('Invalid resource inquiry')
        helper=str(Path(__file__).with_name('_system_exec.py').resolve())
        try:return _capture([sys.executable,'-I','-B','-S',helper,kind,str(sample_seconds)],limit=1048576)
        except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):return Result('unavailable')

    def read_service_properties(self, unit):
        validate_service_unit(unit)
        executable=trusted_tool('systemctl')
        if executable is None: return Result('missing')
        try:
            return _capture([executable,'show','--no-pager','--no-ask-password','--all',
                '--property='+','.join(SERVICE_PROPERTIES),'--',unit],utc=True)
        except (OSError,ValueError,UnicodeError,subprocess.SubprocessError): return Result('unavailable')

    def read_service_journal(self, unit):
        validate_service_unit(unit)
        executable=trusted_tool('journalctl')
        if executable is None: return Result('missing')
        try:
            return _capture([executable,'--system','--boot=0','--unit='+unit,'--lines=201',
                '--output=json','--no-pager','--quiet',
                '--output-fields=MESSAGE,MESSAGE_ID,_TRANSPORT,_PID,_COMM,_UID,PRIORITY,_BOOT_ID,_SYSTEMD_UNIT,UNIT,OBJECT_SYSTEMD_UNIT,COREDUMP_UNIT,_SYSTEMD_INVOCATION_ID,INVOCATION_ID,JOB_RESULT'],utc=True)
        except (OSError,ValueError,UnicodeError,subprocess.SubprocessError): return Result('unavailable')

    def read_atop(self, date: str, start: int, end: int) -> Result:
        return self._read_atop(date, start, end, extended=False)

    def read_atop_extended(self, date: str, start: int, end: int) -> Result:
        return self._read_atop(date, start, end, extended=True)

    def _read_atop(self, date: str, start: int, end: int, *, extended: bool) -> Result:
        from .recordings import open_recording, recording_date
        recording_date(date)
        if (type(start) is not int or type(end) is not int or not 0 <= start <= end
                or end - start > 7200):
            raise ValueError("Invalid recording time window")
        executable = trusted_tool("atop")
        if executable is None:
            return Result("missing")
        descriptor = None
        try:
            window = [datetime.fromtimestamp(value, timezone.utc).strftime('%Y%m%d%H%M%S')
                      for value in (start, end)]
            descriptor = open_recording(date)
            helper = str(Path(__file__).with_name('_atop_exec.py').resolve())
            from .atop import window_boundary
            profile = ['extended'] if extended else []
            return _capture([sys.executable, '-I', '-B', helper, executable, str(descriptor), *window, *profile],
                            pass_fds=(descriptor,), end_when=lambda output: window_boundary(output, end, extended=extended))
        except (OSError, ValueError, OverflowError, subprocess.SubprocessError):
            return Result("unavailable")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def read_boot(self, boot_id: str) -> Result:
        return self._read_boot(boot_id, system=False)

    def read_login_session_properties(self, identities):
        if (not isinstance(identities,list) or not 1<=len(identities)<=64
                or any(not isinstance(value,str) or not re.fullmatch(r'(?:[0-9]{1,10}|c[0-9]{1,10})',value) for value in identities)
                or len(set(identities))!=len(identities)):
            raise ValueError('Invalid local session identities')
        executable=trusted_tool('loginctl')
        if executable is None:return Result('missing')
        try:
            return _capture([executable,'show-session',*identities,'--no-pager','--no-ask-password','--all',
                '--property=Id','--property=Name','--property=User','--property=TTY','--property=Timestamp',
                '--property=RemoteHost','--property=State','--property=Type','--property=Class'],utc=True)
        except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):return Result('unavailable')

    def read_journal_window(self, since_us, until_us, *, boot_id=None, query=None, system=False):
        """Read one bounded time window; boot identity is an optional filter."""
        validate_window(since_us,until_us)
        if boot_id is None and (since_us is None or until_us is None):
            raise ValueError('Unfiltered journal queries require both time boundaries')
        if boot_id is not None and (not isinstance(boot_id,str) or not re.fullmatch(r'[0-9a-f]{32}',boot_id)):
            raise ValueError('Invalid optional boot filter')
        if type(system) is not bool or (query is not None and (not isinstance(query,str) or query not in EVENT_FILTERS)):
            raise ValueError('Invalid journal query')
        executable=trusted_tool('journalctl')
        if executable is None: return Result('missing')
        arguments=['--lines=501','--output=json','--no-pager','--quiet',
                   '--output-fields=MESSAGE,MESSAGE_ID,_TRANSPORT,_PID,_COMM,_UID,PRIORITY,_BOOT_ID']
        if boot_id is not None: arguments.append('--boot='+boot_id)
        for label,value in (('since',since_us),('until',until_us)):
            if value is not None: arguments.append(f'--{label}=@{value//1000000}.{value%1000000:06d}')
        if query is not None: arguments.extend(EVENT_FILTERS[query])
        if system: arguments.insert(0,'--system')
        try: return _capture([executable,*arguments])
        except (OSError,ValueError,UnicodeError,subprocess.SubprocessError): return Result('unavailable')

    def read_system_boot(self, boot_id: str) -> Result:
        return self._read_boot(boot_id, system=True)

    def read_boot_until(self, boot_id: str, until_us: int, *, system=False) -> Result:
        if type(until_us) is not int or not 0 <= until_us <= MAX_REALTIME_US:
            raise ValueError("Invalid journal time boundary")
        return self._read_boot(boot_id, system=system, until_us=until_us)

    def read_boot_window(self, boot_id: str, since_us: int, *, until_us=None, system=False) -> Result:
        if since_us is None:
            raise ValueError("A journal start boundary is required")
        validate_window(since_us, until_us)
        return self._read_boot(boot_id, system=system, since_us=since_us, until_us=until_us)

    def read_event_candidates(self, boot_id: str, query: str, *, system=False, since_us=None, until_us=None) -> Result:
        if not isinstance(query, str) or query not in EVENT_FILTERS:
            raise ValueError("Invalid event query")
        return self._read_boot(boot_id, system=system, query=query, since_us=since_us, until_us=until_us)

    def read_ssh_candidates(self, boot_id: str, *, system=False, since_us=None, until_us=None) -> Result:
        return self._read_boot(boot_id, system=system, query='ssh_events', since_us=since_us, until_us=until_us)

    def read_firewall_candidates(self, boot_id: str, *, system=False, since_us=None, until_us=None) -> Result:
        return self._read_boot(boot_id, system=system, query='firewall_events', since_us=since_us, until_us=until_us)

    def _read_boot(self, boot_id: str, *, system: bool, query=None, until_us=None, since_us=None) -> Result:
        validate_window(since_us, until_us)
        if query is not None and (not isinstance(query, str) or query not in EVENT_FILTERS):
            raise ValueError("Invalid event query")
        if type(system) is not bool:
            raise ValueError("Invalid journal scope")
        if not isinstance(boot_id, str) or not re.fullmatch(r"[0-9a-f]{32}", boot_id):
            raise ValueError("Invalid boot identity")
        executable = trusted_tool("journalctl")
        if executable is None:
            return Result("missing")
        arguments = ["--boot=" + boot_id, "--lines=501", "--output=json", "--no-pager", "--quiet",
                     "--output-fields=MESSAGE,MESSAGE_ID,_TRANSPORT,_PID,_COMM"]
        if query is not None:
            arguments[-1] += ",PRIORITY"
            if query == 'ssh_events':
                arguments[-1] += ',_UID'
            arguments.extend(EVENT_FILTERS[query])
        if since_us is not None:
            arguments.append(f"--since=@{since_us // 1000000}.{since_us % 1000000:06d}")
        if until_us is not None:
            arguments.append(f"--until=@{until_us // 1000000}.{until_us % 1000000:06d}")
        if system:
            arguments.insert(0, "--system")
        try:
            return _capture([executable, *arguments])
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            return Result("unavailable")

    def available(self, name: str) -> bool:
        return trusted_tool(name) is not None

    def run(self, command: Command) -> Result:
        tool, arguments = CATALOG[command]
        executable = trusted_tool(tool)
        if executable is None:
            return Result("missing")
        try:
            if command==Command.LOGIN_SESSIONS:
                return _capture([executable,*arguments],utc=True)
            return _capture([executable, *arguments])
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            return Result("unavailable")
