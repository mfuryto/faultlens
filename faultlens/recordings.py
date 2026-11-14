"""Read descriptors for fixed, trusted local recordings without following links."""
from datetime import datetime
import os
import re
import stat

MAX_RECORDING_BYTES = 256 * 1024 * 1024


def recording_date(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{8}', value):
        raise ValueError('Recording date must be YYYYMMDD')
    parsed = datetime.strptime(value, '%Y%m%d')
    if parsed.year < 1970:
        raise ValueError('Unsupported recording date')
    return value


def trusted_metadata(metadata, directory=False, allow_group_write=False):
    forbidden = stat.S_IWOTH | (0 if directory and allow_group_write else stat.S_IWGRP)
    if metadata.st_uid != 0 or metadata.st_mode & forbidden:
        raise ValueError('Recording path is not root-controlled')
    if directory:
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError('Recording ancestor is not a directory')
    elif not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_RECORDING_BYTES:
        raise ValueError('Recording is not a bounded regular file')


def open_recording(date: str) -> int:
    """Caller owns the returned read-only fd. Never accept an arbitrary path."""
    recording_date(date)
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        trusted_metadata(os.fstat(directory), directory=True)
        for name in ('var', 'log', 'atop'):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
            # Some distributions give syslog write access to /var/log. The next
            # root-owned non-writable atop directory and final inode are pinned.
            trusted_metadata(os.fstat(directory), directory=True, allow_group_write=name == 'log')
        descriptor = os.open('atop_' + date, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        try:
            trusted_metadata(os.fstat(descriptor))
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(directory)
