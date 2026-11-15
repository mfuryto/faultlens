"""Read-only server acceptance orchestration; missing evidence is not a test failure."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import sys
import subprocess

from . import __version__
from .commands import _capture

ROOT = Path(__file__).resolve().parents[1]
STATES = ('PASS', 'WARN', 'MISSING', 'SKIP', 'FAIL')
WORKERS = ('unit', 'policy', 'benchmark', 'profiles', 'status', 'health', 'network', 'history', 'diagnose', 'compare')
REPOSITORY = {'unit', 'policy', 'benchmark', 'profiles'}


def row(key, state, message, advice=''):
    if state not in STATES:
        raise ValueError('Unknown check state')
    return {'key': key, 'state': state, 'message': message, 'advice': advice}


def observation_rows(prefix, observations):
    result = []
    for value in observations:
        state = ('MISSING' if value.state == 'unavailable' or value.value is None else
                 'WARN' if value.state in {'warning', 'critical'} or value.value is False else 'PASS')
        result.append(row(prefix+'.'+value.key, state,
            'Source/value unavailable.' if state == 'MISSING' else
            'Service reports '+value.value+'.' if isinstance(value.value,str) and value.value in {'inactive','failed'} else
            'Observation classified '+value.state+'; this is not a program-test failure.' if state == 'WARN' else
            'Observation collected; this does not assert host health.',
            value.explanation if state != 'PASS' else ''))
    return result


def source_row(key, data, detail=''):
    state = data.get('state')
    reason = data.get('reason')
    advice = ''
    if state not in {'available','not_requested'}:
        advice = 'Inspect existing access, retention, dependency availability and supported format; no changes were attempted.'
        metadata = data if 'command_state' in data else data.get('journal_collection') or data.get('boot_listing') or {}
        if metadata.get('command_state'):
            advice += ' Command state: '+str(metadata['command_state'])+'; exit '+str(metadata.get('returncode'))+'.'
    return row(key, 'PASS' if state == 'available' else 'WARN' if state == 'partial' else
               'SKIP' if state == 'not_requested' else 'MISSING',
        detail or 'Source state: ' + str(state) + ('. Reason: '+str(reason) if reason else ''), advice)


def live_probe(name, *, boot=0, atop_date=None, pstore=False):
    from .collectors import status, check
    from .commands import CommandRunner
    from .incidents import diagnose
    from .network import collect
    from .overview import incidents
    runner = CommandRunner()
    if name == 'status':
        return observation_rows('status', status(runner=runner))
    if name == 'health':
        from .preservation import assess
        return observation_rows('health', check(runner=runner)+assess(runner=runner))
    if name == 'network':
        from .sockets import attach
        data = collect(sample_seconds=0.1)
        attach(data, runner)
        results = [source_row('network.counters',data), source_row('network.sockets',data['sockets'])]
        results += [row('network.'+str(i)+'.'+value['key'], 'MISSING', 'Counter observation unavailable.')
                    for i,value in enumerate(data['observations']) if value['state'] == 'unavailable']
        if data['findings']:
            results.append(row('network.counter_growth','WARN','Supported pressure/error counters increased; attack and cause remain Unknown.',
                               'Inspect faultlens security --sockets locally.'))
        return results
    if name == 'history':
        results = []
        for system in (False, True):
            scope = 'system' if system else 'visible'
            data = incidents(runner, system_journal=system)
            results.append(source_row('history.'+scope,data))
            results.append(row('history.'+scope+'.previous_boots', 'PASS' if data['selected_boot_count'] else 'MISSING',
                str(data['selected_boot_count'])+' previous boots selected for bounded summaries.'))
        return results
    if name == 'diagnose':
        results = []
        for system in (False, True):
            prefix = 'diagnose.'+('system' if system else 'visible')
            data = diagnose(runner, boot_index=boot, system_journal=system,
                search_ssh=True, search_firewall=True, atop_date=atop_date, atop_extended=bool(atop_date))
            results.append(source_row(prefix,data, 'Selected-boot diagnosis state: '+data['state']+'.'))
            for field in ('ssh_analysis','firewall_analysis','atop'):
                source = data[field]
                results.append(source_row(prefix+'.'+field,source))
                if field != 'atop' and source['state'] == 'available':
                    count = source['candidates_examined']
                    results.append(row(prefix+'.'+field+'.coverage', 'PASS' if count else 'MISSING',
                        str(count)+' candidates examined; empty evidence cannot test positive detections.'))
                    matches=len(source['findings'])
                    results.append(row(prefix+'.'+field+'.signatures','PASS' if matches else 'MISSING',
                        str(matches)+' supported event reports classified; confirms formats, not an attack.'))
            comparison = data['security_analysis']['historical_comparison']
            results.append(row(prefix+'.traffic_baseline', 'SKIP' if not atop_date else
                'PASS' if comparison['state'] == 'compared' else 'MISSING',
                'Historical comparison: '+comparison['state']+'.',
                'At least six comparable contiguous extended samples are required; no history is invented.'))
            if data['security_analysis']['matching_indicators']:
                results.append(row(prefix+'.indicators','WARN',
                    'Possible security indicators matched; this is not a confirmed attack or program failure.',
                    'Inspect the referenced original evidence with faultlens diagnose locally.'))
        if pstore:
            from .pstore import analyze
            from .pstore_archive import analyze as archive
            for label, collector in (('pstore.live',analyze),('pstore.archive',archive)):
                source=collector()
                results.append(source_row(label,source))
                if source['state']=='available':
                    results.append(row(label+'.records','PASS' if source['records'] else 'MISSING',
                                       str(len(source['records']))+' supported records visible; absence does not exclude a crash.'))
        else:
            results.append(row('pstore','SKIP','Crash-evidence readers were not requested.','Use --pstore to test both fixed readers.'))
        return results
    if name == 'compare':
        from .validation import validate
        return [row('compare.'+value['key'], 'PASS' if value['state']=='pass' else
                    'MISSING' if value['state']=='unavailable' else 'WARN',
                    'Reference comparison: '+value['state']+'.',
                    'Busy-system timing can cause differences; inspect scripts/validate_local.py before diagnosing a bug.'
                    if value['state']=='mismatch' else '') for value in validate()['comparisons']]
    raise ValueError('Unknown live probe')


def terminal_rows():
    from importlib.metadata import version,PackageNotFoundError
    try: installed=version('textual')
    except PackageNotFoundError:
        return [row('tui.textual','MISSING','Optional Textual frontend is unavailable.',
                    'Use the reviewed requirements-tui.txt in an isolated environment. The CLI remains usable.')]
    result=[row('tui.textual','PASS' if installed=='8.2.8' else 'MISSING',
                'Reviewed Textual frontend is installed.' if installed=='8.2.8' else 'Frontend version differs from the reviewed lock.')]
    terminal=os.environ.get('TERM','')
    if not getattr(sys.stdin,'isatty',lambda:False)() or not getattr(sys.stdout,'isatty',lambda:False)():
        result.append(row('tui.current_terminal','SKIP','Current input/output is not an interactive terminal.'))
    elif terminal=='dumb' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,63}',terminal):
        result.append(row('tui.current_terminal','MISSING','TERM is absent or unsupported.'))
    else: result.append(row('tui.current_terminal','PASS','Interactive terminal declared; actual rendering requires manual acceptance.'))
    result.append(row('tui.manual_navigation','SKIP','Human SSH/navigation acceptance requires an interactive check.',
                      'Run .venv/bin/python bin/faultlens tui; test Left/Right tabs, Up/Down rows, Enter, Esc, e, r, resize, q and Ctrl-C.'))
    return result



def run_worker(name, *, boot=0, atop_date=None, pstore=False):
    """Fixed worker dispatch. Process-local cwd/limits never change server settings."""
    if name not in WORKERS:
        raise ValueError('Unknown worker')
    sys.stderr = sys.stdout
    os.chdir(ROOT)
    if name == 'unit':
        sys.argv = ['unittest','discover','-s',str(ROOT/'tests'),'-t',str(ROOT),'-q']
        runpy.run_module('unittest',run_name='__main__')
    elif name in REPOSITORY:
        script, arguments = {
            'policy':('security_check.py',[]),
            'benchmark':('benchmark.py',['--iterations','10','--json']),
            'profiles':('vps_acceptance.py',['--iterations','3','--json']),
        }[name]
        sys.argv = [script,*arguments]
        runpy.run_path(str(ROOT/'scripts'/script),run_name='__main__')
    else:
        print(json.dumps({'checks':live_probe(name,boot=boot,atop_date=atop_date,pstore=pstore)},ensure_ascii=True,allow_nan=False))


def worker_argv(name, *, boot=0, atop_date=None, pstore=False):
    if name not in WORKERS:
        raise ValueError('Unknown worker')
    from .cli import boot_index
    from .recordings import recording_date
    boot=boot_index(str(boot))
    if atop_date is not None:
        recording_date(atop_date)
    return [sys.executable,'-I','-B',str(ROOT/'scripts/server_check.py'),'--worker',name,
            '--boot',str(boot),*(['--atop-date',atop_date] if atop_date else []),*(['--pstore'] if pstore else [])]


def capture_worker(argv, *, timeout, limit):
    return _capture(argv, timeout=timeout, limit=limit, graceful=True)


def check_server(*, live_only=False, boot=0, atop_date=None, pstore=False, details=False,
                 execute=capture_worker, progress=None, terminal=terminal_rows, uid=None, owner=None):
    # Validate all selectors before launching any child or reading native evidence.
    worker_argv('diagnose',boot=boot,atop_date=atop_date,pstore=pstore)
    uid=os.geteuid() if uid is None else uid
    owner=ROOT.stat().st_uid if owner is None else owner
    checks=terminal()
    missing_frontend=any(value['key']=='tui.textual' and value['state']=='MISSING' for value in checks)
    missing_git=shutil.which('git',path='/usr/bin:/usr/sbin:/bin:/sbin') is None
    for name in WORKERS:
        if name in REPOSITORY and (live_only or uid==0 or uid!=owner):
            checks.append(row('repository.'+name,'SKIP',
                'Repository tests skipped by --live-only.' if live_only else
                'Repository checks must run as the non-root checkout owner; no Git trust exception was added.',
                'Run .venv/bin/python scripts/server_check.py as the checkout owner.'))
            continue
        if (missing_frontend and name in {'unit','benchmark','profiles'}) or (missing_git and name in {'unit','policy'}):
            checks.append(row('repository.'+name,'MISSING','Complete repository acceptance requires '+
                ('reviewed Textual frontend' if missing_frontend and name in {'unit','benchmark','profiles'} else 'Git')+'.',
                'Explicit live CLI probes remain independent; no dependency was installed.'))
            continue
        if progress:
            progress(name)
        try:
            result=execute(worker_argv(name,boot=boot,atop_date=atop_date,pstore=pstore),timeout=120 if name in REPOSITORY else 60,limit=4194304)
        except (OSError,UnicodeError,subprocess.SubprocessError):
            checks.append(row(('repository.' if name in REPOSITORY else 'probe.')+name,
                'FAIL' if name in REPOSITORY else 'WARN','Check could not start or finish; results unavailable.'))
            continue
        if result.state!='completed' or result.returncode!=0:
            item=row(('repository.' if name in REPOSITORY else 'probe.')+name,
                'FAIL' if name in REPOSITORY or result.state=='completed' else 'WARN',
                'Check did not complete successfully: '+result.state+'; exit '+str(result.returncode)+'.',
                'Inspect this check independently. Native timeout/resource failure is not proof of a software bug.')
            if details and name in REPOSITORY and result.stdout:
                # Excerpts are explicit, bounded and rendered with reversible JSON escaping.
                item['details']=result.stdout[-6000:]
                item['details_truncated']=len(result.stdout)>6000
            checks.append(item)
            continue
        if name in REPOSITORY:
            checks.append(row('repository.'+name,'PASS','Automated check completed successfully.'))
            continue
        try:
            parsed=json.loads(result.stdout)
            values=parsed['checks']
            if (not isinstance(values,list) or not values or len(values)>200 or
                any(not isinstance(value,dict) or set(value)!={'key','state','message','advice'} or
                    value['state'] not in STATES or not all(isinstance(value[k],str) for k in value)
                    for value in values)):
                raise ValueError('Invalid check response')
            checks.extend(values)
        except (ValueError,KeyError,TypeError,RecursionError):
            checks.append(row('probe.'+name,'FAIL','Probe returned an invalid structured summary.'))
    counts={state:sum(item['state']==state for item in checks) for state in STATES}
    return {'schema_version':1,'version':__version__,'command':'server-check',
            'collected_at':datetime.now(timezone.utc).isoformat(),
            'overall':'FAIL' if counts['FAIL'] else 'ATTENTION' if counts['WARN'] or counts['MISSING'] else 'PASS',
            'counts':counts,'checks':checks,
            'limitations':['Read-only checks never install tools, elevate, change services/configuration or save diagnostic reports.',
                'PASS means this check worked, not that the server is healthy, secure or attack-free.',
                'Missing tools, restricted access, empty history and insufficient baselines are distinguished from failed program tests.',
                'Native collection uses current access rights. Optional raw evidence is analyzed in memory; this summary contains statuses rather than logs.',
                'Constrained process profiles and synthetic PTY tests are not full VPS or remote-SSH deployment acceptance.']}


def exit_code(data):
    return 1 if data['counts']['FAIL'] else 0
