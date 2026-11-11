"""A fixed read-only command catalog with bounded output and execution time."""
from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time


class Command(Enum):
    REFERENCE_MEMORY = "reference_memory"
    REFERENCE_FILESYSTEM = "reference_filesystem"
    SYSTEM_STATE = "system_state"
    JOURNAL_BOOTS = "journal_boots"
    JOURNAL_SERVICE = "journal_service"
    ATOP_SERVICE = "atop_service"


CATALOG = {
    Command.REFERENCE_MEMORY: ("free", ("--bytes",)),
    Command.REFERENCE_FILESYSTEM: ("df", ("--block-size=1", "--output=size,used,avail,pcent", "/")),
    Command.SYSTEM_STATE: ("systemctl", ("is-system-running", "--no-pager")),
    Command.JOURNAL_BOOTS: ("journalctl", ("--list-boots", "--no-pager", "--quiet", "--no-legend")),
    Command.JOURNAL_SERVICE: ("systemctl", ("is-active", "systemd-journald.service", "--no-pager")),
    Command.ATOP_SERVICE: ("systemctl", ("is-active", "atop.service", "--no-pager")),
}
TOOLS = ("free", "df", "systemctl", "journalctl", "ip", "ss", "nstat", "nft", "atop", "sar", "sosreport")
DIRECTORIES = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
ENVIRONMENT = {"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "LANG": "C", "LC_ALL": "C",
               "SYSTEMD_PAGER": "", "PAGER": "", "SYSTEMD_COLORS": "0"}


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


def _capture(argv: list[str], timeout: float = 2.0, limit: int = 262144) -> Result:
    """Drain both pipes without communicate's unbounded in-memory buffering."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, env=ENVIRONMENT,
                               cwd="/", start_new_session=True)
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
            return Result("completed", output.decode("utf-8", errors="strict"), process.returncode)
    finally:
        # Also kill descendants retaining pipes after the direct child exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=1)
        process.stdout.close()
        process.stderr.close()


class CommandRunner:
    def available(self, name: str) -> bool:
        return trusted_tool(name) is not None

    def run(self, command: Command) -> Result:
        tool, arguments = CATALOG[command]
        executable = trusted_tool(tool)
        if executable is None:
            return Result("missing")
        try:
            return _capture([executable, *arguments])
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            return Result("unavailable")
