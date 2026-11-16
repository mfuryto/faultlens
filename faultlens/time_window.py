"""Exact explicit-offset incident times; no host timezone, clock reads or float epochs."""
from datetime import datetime,timedelta,timezone
import re

from .journal import MAX_REALTIME_US

EPOCH=datetime(1970,1,1,tzinfo=timezone.utc)
FORMAT=re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z')
FORMAT_HELP='Use an explicit date/time with timezone, e.g. 2026-11-14T23:20:00+01:00 or 2026-11-14T22:20:00Z.'
HELP=FORMAT_HELP+' Empty clears the boundary; existing Unix microseconds also work.'


def parse(value,*,allow_microseconds=False):
    if not isinstance(value,str) or len(value)>64 or not value.isascii(): raise ValueError('Invalid incident time')
    if allow_microseconds and value.isdecimal():
        if len(value)>18 or int(value)>MAX_REALTIME_US: raise ValueError('Incident time out of range')
        return int(value)
    if not FORMAT.fullmatch(value): raise ValueError(FORMAT_HELP)
    if int(value[11:13])>23 or int(value[14:16])>59 or (value[16:17]==':' and int(value[17:19])>59):
        raise ValueError('Invalid clock time')
    if value[-1]!='Z' and (int(value[-5:-3])>23 or int(value[-2:])>59): raise ValueError('Invalid timezone offset')
    try:
        moment=datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)
        delta=moment-EPOCH
    except (ValueError,OverflowError) as exc: raise ValueError('Invalid incident date, time or offset') from exc
    result=(delta.days*86400+delta.seconds)*1000000+delta.microseconds
    if not 0<=result<=MAX_REALTIME_US: raise ValueError('Incident time out of range')
    return result


def display(value):
    if not value: return 'Not selected'
    result=parse(value,allow_microseconds=True)
    return (EPOCH+timedelta(microseconds=result)).isoformat(timespec='microseconds').replace('+00:00','Z')
