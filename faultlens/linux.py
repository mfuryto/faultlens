"""Bounded access to known Linux sources; no arbitrary CLI-supplied paths."""
import os
from pathlib import Path
import stat


class LinuxSources:
    def read(self, path: str, limit: int = 262144) -> str:
        # O_NONBLOCK avoids hanging on a FIFO before fstat can reject it.
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Source is not a regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise ValueError("Source exceeds size limit")
            return data.decode("utf-8", errors="strict")
        finally:
            os.close(fd)

    def filesystem(self):
        return os.statvfs("/")

    def directory(self, path: str) -> bool:
        return Path(path).is_dir()

    def process_count(self) -> int:
        count = 0
        with os.scandir("/proc") as entries:
            for index, entry in enumerate(entries):
                if index >= 32768:
                    raise ValueError("Process enumeration exceeds limit")
                if entry.name.isascii() and entry.name.isdecimal():
                    count += 1
        return count
