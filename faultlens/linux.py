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

    def log_filesystem(self, kind: str):
        from .recordings import open_log_directory
        directory = open_log_directory(kind)
        try:
            return os.fstatvfs(directory)
        finally:
            os.close(directory)

    def recording_inventory(self) -> dict:
        from .recordings import MAX_RECORDING_BYTES, open_log_directory, recording_date
        import re
        directory = open_log_directory('atop')
        result = {'files': 0, 'logical_bytes': 0, 'empty_files': 0, 'oversized_files': 0,
                  'unsafe_entries': 0, 'unsupported_entries': 0, 'oldest_date': None, 'newest_date': None}
        dates = []
        try:
            with os.scandir(directory) as entries:
                for index, entry in enumerate(entries):
                    if index >= 512:
                        raise ValueError('Recording inventory exceeds limit')
                    if not entry.name.startswith('atop_'):
                        continue
                    if not re.fullmatch(r'atop_[0-9]{8}', entry.name):
                        result['unsupported_entries'] += 1
                        continue
                    try:
                        date = recording_date(entry.name[5:])
                    except ValueError:
                        result['unsupported_entries'] += 1
                        continue
                    metadata = entry.stat(follow_symlinks=False)
                    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or metadata.st_size < 0):
                        result['unsafe_entries'] += 1
                        continue
                    result['files'] += 1
                    result['logical_bytes'] += metadata.st_size
                    result['empty_files'] += metadata.st_size == 0
                    result['oversized_files'] += metadata.st_size > MAX_RECORDING_BYTES
                    dates.append(date)
            if dates:
                result.update(oldest_date=min(dates), newest_date=max(dates))
            from .coverage import date_gaps
            result['filename_coverage'] = date_gaps(dates)
            return result
        finally:
            os.close(directory)
