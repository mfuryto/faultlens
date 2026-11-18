"""Bounded per-user TUI preferences; never persist diagnostic evidence."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import secrets
import stat

from .tui_model import Settings

MAX_BYTES=8192
DIRECTORY_FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC


def validated(values):
    """Validate a complete versioned snapshot before using any of its values."""
    from .cli import atop_date,boot_identity,boot_index,interval,overview_count,receipt_boundary
    from .journal import validate_window
    template=asdict(Settings())
    if not isinstance(values,dict) or set(values)!=set(template): raise ValueError('Invalid settings fields')
    for key,default in template.items():
        value=values[key]
        if type(default) is float:
            if type(value) not in {int,float}: raise ValueError('Invalid numeric setting')
        elif type(value) is not type(default): raise ValueError('Invalid setting type')
        if isinstance(value,str) and (len(value)>64 or any(not 32<=ord(c)<=126 for c in value)):
            raise ValueError('Invalid setting text')
    result=dict(values)
    selector=result['boot_selector']
    result['boot_selector']=(boot_identity(selector) if len(selector)==32 else str(boot_index(selector))) if selector else ''
    if result['investigation_mode'] not in {'','now','period','before-restart'}: raise ValueError('Invalid investigation entry')
    result['sample_seconds']=interval(str(result['sample_seconds']))
    result['boot_count']=overview_count(str(result['boot_count']))
    if result['atop_date']: result['atop_date']=atop_date(result['atop_date'])
    for key in ('since_us','until_us'):
        if result[key]: result[key]=str(receipt_boundary(result[key]))
    validate_window(int(result['since_us']) if result['since_us'] else None,
                    int(result['until_us']) if result['until_us'] else None)
    if not result['investigation_mode'] and not result['boot_selector']: raise ValueError('Technical reader requires an explicit boot selector')
    if result['investigation_mode']=='period' and (not result['since_us'] or not result['until_us']): raise ValueError('Period requires both boundaries')
    if result['atop_extended'] and not result['atop_date']: raise ValueError('Missing recording date')
    return Settings(**result)


def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('Duplicate preference field')
        result[key]=value
    return result


class SettingsStore:
    def __init__(self,base=None):
        if base is None:
            configured=os.environ.get('XDG_CONFIG_HOME','')
            base=Path(configured) if configured and Path(configured).is_absolute() else Path.home()/'.config'
        self.base=Path(base)
        if not self.base.is_absolute() or '..' in self.base.parts: raise ValueError('Invalid configuration directory')
        self.path=self.base/'faultlens'/'settings.json'

    def directory(self,create=False):
        """Walk with directory descriptors so no symlink component is followed."""
        fd=os.open('/',DIRECTORY_FLAGS)
        try:
            for part in self.base.parts[1:]:
                try: child=os.open(part,DIRECTORY_FLAGS,dir_fd=fd)
                except FileNotFoundError:
                    if not create: raise
                    os.mkdir(part,0o700,dir_fd=fd)
                    child=os.open(part,DIRECTORY_FLAGS,dir_fd=fd)
                os.close(fd); fd=child
            info=os.fstat(fd)
            if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o022:
                raise ValueError('Unsafe configuration directory')
            if create:
                try: os.mkdir('faultlens',0o700,dir_fd=fd)
                except FileExistsError: pass
            child=os.open('faultlens',DIRECTORY_FLAGS,dir_fd=fd)
            os.close(fd); fd=child
            info=os.fstat(fd)
            if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o077:
                raise ValueError('Unsafe preference directory')
            return fd
        except BaseException:
            os.close(fd); raise

    def read_file(self,directory):
        fd=os.open('settings.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode)&0o077 or info.st_size>MAX_BYTES):
                raise ValueError('Unsafe preference file')
            data=os.read(fd,MAX_BYTES+1)
            if len(data)>MAX_BYTES: raise ValueError('Preference size limit')
            return data
        finally: os.close(fd)

    def load(self,defaults):
        try:
            directory=self.directory()
            try: data=self.read_file(directory)
            finally: os.close(directory)
            value=json.loads(data.decode('utf-8'),object_pairs_hook=unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite preference')))
            if (not isinstance(value,dict) or set(value)!={'schema_version','settings'}
                    or type(value['schema_version']) is not int or value['schema_version'] not in {1,2}):
                raise ValueError('Unsupported preference format')
            if value['schema_version']==1:
                previous=value['settings']
                expected=set(asdict(Settings()))-{'investigation_mode'}
                if not isinstance(previous,dict) or set(previous)!=expected: raise ValueError('Invalid legacy preference fields')
                migrated=dict(previous)
                migrated['investigation_mode']=('period' if previous.get('since_us') and previous.get('until_us') else
                    '' if previous.get('since_us') or previous.get('until_us') else 'before-restart')
                return validated(migrated),'Migrated boot-scoped preferences; previous filter retained. Choose Problems now or A selected period for an unfiltered inquiry.'
            return validated(value['settings']),'Preferences loaded for this user.'
        except FileNotFoundError: return defaults,'Preferences: defaults; changes will be saved.'
        except (OSError,ValueError,RecursionError,argparse.ArgumentTypeError):
            return defaults,'Saved preferences unavailable or invalid; defaults in use.'

    def save(self,settings):
        payload=json.dumps({'schema_version':2,'settings':asdict(validated(asdict(settings)))},
                           ensure_ascii=True,allow_nan=False,indent=2).encode()+b'\n'
        if len(payload)>MAX_BYTES: raise ValueError('Preference size limit')
        directory=self.directory(create=True); temporary='.settings-'+secrets.token_hex(16)
        try:
            try: self.read_file(directory)
            except FileNotFoundError: pass
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
            try:
                os.fchmod(fd,0o600)
                with os.fdopen(fd,'wb',closefd=False) as output:
                    output.write(payload); output.flush(); os.fsync(fd)
            finally: os.close(fd)
            os.replace(temporary,'settings.json',src_dir_fd=directory,dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try: os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError: pass
            finally: os.close(directory)
