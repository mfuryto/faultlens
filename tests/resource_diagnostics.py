"""Bounded synthetic resource metadata; never print worker traceback or source data."""
import json
import math
import re
import subprocess

MODES={'status','health','check','history','diagnose','diagnose-atop','check-history','diagnose-pstore',
       'diagnose-pstore-archive','diagnose-stalls','diagnose-clock','diagnose-system','diagnose-events',
       'diagnose-review','diagnose-overlay','diagnose-journal-loss','incidents','diagnose-integrated',
       'diagnose-extended','network','security','diagnose-ssh','diagnose-firewall','network-sockets',
       'phase3-security','tui-status','tui-diagnostic','tui-health'}


def number(value):
    return str(round(value,4)) if type(value) in {int,float} and math.isfinite(value) and 0<=value<1e9 else 'unknown'


def emit(result):
    if not result.returncode:return
    try:data=json.loads(result.stdout)
    except (ValueError,TypeError):
        match=re.search(r"--worker[\s'\",]+([a-z-]+)",result.stderr or '')
        mode=match[1] if match and match[1] in MODES else 'unknown'
        print('Resource worker failed: '+mode);return
    rows=[(mode,item) for mode,item in data.get('commands',{}).items() if not item.get('within_regression_budget')]
    rows += [(item['mode'],item) for item in data.get('profiles',[]) if not item.get('passed')]
    for mode,item in rows[:32]:
        if mode not in MODES:continue
        print('Resource check: '+mode+' cpu='+number(item.get('cpu_max_seconds',item.get('cpu_seconds')))+
              ' wall='+number(item.get('startup_wall_max_seconds',item.get('wall_seconds')))+
              ' rss='+number(item.get('peak_rss_max_mib',item.get('peak_rss_mib')))+
              ' memory='+number(item.get('address_space_limit_mib',item.get('memory_mib'))))


def capture(argv,**options):
    try:return subprocess.run(argv,**options)
    except subprocess.TimeoutExpired:
        kind='benchmark' if str(argv[2]).endswith('/benchmark.py') else 'profiles'
        print('Resource suite timed out: '+kind+' after='+number(options.get('timeout')))
        raise
