"""Human-readable test presentation; source results and exit decisions stay unchanged."""
import json
import textwrap

REPO_NAMES = {'repository.unit':'Automated software tests', 'repository.policy':'Repository security checks',
              'repository.benchmark':'Performance tests', 'repository.profiles':'Constrained resource tests'}
METRIC_NAMES = {'memory.total':'Total RAM', 'memory.used':'RAM usage', 'swap.total':'Total swap',
    'filesystem.root.total':'Root filesystem size', 'filesystem.root.used':'Root filesystem usage',
    'filesystem.root.user_used':'Root filesystem usage for ordinary users',
    'system.kernel_release':'Kernel version', 'system.uptime':'System uptime'}
PROGRESS_NAMES = {'unit':'automated software and TUI tests', 'policy':'repository security checks',
    'benchmark':'performance tests', 'profiles':'constrained resource tests', 'status':'current system measurements',
    'health':'tools, services and recording setup', 'network':'network counters and sockets',
    'history':'accessible boot history', 'diagnose':'journal and optional historical evidence',
    'investigate':'Problems now, recent period and before-restart investigations',
    'compare':'measurement comparisons'}


def safe(text):
    return json.dumps(str(text), ensure_ascii=True)[1:-1]


def section(out, title, messages):
    print('\n'+title, file=out)
    for message in messages:
        lines=textwrap.wrap(safe(message),width=88,initial_indent='  - ',subsequent_indent='    ')
        print('\n'.join(lines),file=out)


def label(key):
    if key in REPO_NAMES:
        return REPO_NAMES[key]
    if key.startswith('health.dependency.'):
        return 'Optional tool '+key.removeprefix('health.dependency.')
    if key.startswith('status.') and key.removeprefix('status.') in METRIC_NAMES:
        return METRIC_NAMES[key.removeprefix('status.')]
    readable={'network.context.addresses':'Local address/link source','network.context.routes4':'IPv4 route source',
        'network.context.routes6':'IPv6 route source','network.context.owners':'Reported socket-owner source',
        'network.intervals':'Repeated short network samples','status.cpu.busy':'CPU usage', 'status.swap.used':'Used swap',
        'status.filesystem.root.available':'Available root filesystem space',
        'health.atop.service_active':'Atop recording service', 'health.journal.service_active':'System journal service',
        'network.counter_growth':'Network pressure/error counters',
        'history.visible.previous_boots':'Accessible previous-boot history',
        'health.failed_services':'Failed-service source', 'health.failed_service_observations':'Failed service units',
        'tui.current_terminal':'Interactive terminal check', 'tui.textual':'Reviewed Textual frontend',
        'health.journal.config':'Journal configuration'}
    if key in readable:
        return readable[key]
    if key.startswith('probe.') and key.removeprefix('probe.') in PROGRESS_NAMES:
        return PROGRESS_NAMES[key.removeprefix('probe.')].capitalize()
    if key.startswith('compare.'):
        return METRIC_NAMES.get(key.removeprefix('compare.'),'Measurement comparison')
    return key.replace('_',' ').replace('.',' / ').capitalize()


def server_summary(data):
    """Group explanations, never reinterpret source availability as host health."""
    rows=data['checks']
    covered=set()
    worked, unavailable, actions, attention = [], [], [], []
    def take(predicate):
        selected=[r for i,r in enumerate(rows) if i not in covered and predicate(r)]
        covered.update(i for i,r in enumerate(rows) if i not in covered and predicate(r))
        return selected
    def select_state(key, state):
        return any(r['key']==key and r['state']==state for r in rows)

    for item in take(lambda r:r['state'] in {'WARN','FAIL'}):
        attention.append(label(item['key'])+': '+item['message'])
    if any(r['state']=='FAIL' for r in rows):
        actions.append('Review the failed checks with --details. A failed check needs investigation; it does not by itself identify a software bug.')
    if any(r['state']=='WARN' for r in rows):
        actions.append('Review the reported observations or comparison differences in --details before deciding whether any action is needed.')

    repo=take(lambda r:r['key'] in REPO_NAMES and r['state']=='PASS')
    if len(repo)==4:
        worked.append('Software tests, repository security checks, performance tests and constrained resource tests passed.')
    else:
        worked.extend(REPO_NAMES[r['key']]+' passed.' for r in repo)
    for prefix,description in (('status.','System measurements collected'),('health.dependency.','Optional tools detected'),
                               ('health.','Service, logging and recording checks completed')):
        values=take(lambda r:r['key'].startswith(prefix) and r['state']=='PASS')
        if values:
            worked.append(description+': '+str(len(values))+'.')
    for key,description in (('network.counters','Current network counters were read.'),
            ('network.sockets','The local socket snapshot was read.'),
            ('network.intervals','Three independent short network intervals were retained; they are not a baseline or continuous recording.'),
            ('history.visible','Accessible boot history was read.'),('history.system','System journal boot history was read.'),
            ('tui.textual','Reviewed Textual frontend is available.'),('tui.current_terminal','Your current terminal declares interactive support; rendering still needs a manual check.')):
        if take(lambda r:r['key']==key and r['state']=='PASS'):
            worked.append(description)
    comparisons=take(lambda r:r['key'].startswith('compare.') and r['state']=='PASS')
    if comparisons:
        worked.append(str(len(comparisons))+' reference measurements agreed within the allowed tolerances.')
    if take(lambda r:r['key'].endswith('.traffic_baseline') and r['state']=='PASS'):
        worked.append('A recorded traffic-baseline comparison was exercised.')
    crash_read=take(lambda r:r['key'].startswith('pstore') and r['state']=='PASS')
    if crash_read:
        worked.append('Available persistent crash-evidence readers responded.')
    diagnostic=take(lambda r:r['key'].startswith('diagnose.') and r['state']=='PASS')
    if diagnostic:
        worked.append('Journal and diagnostic queries completed where evidence was accessible.')
    for scope in ('visible', 'system'):
        for mode, name in (('now', 'Problems now'), ('period', 'Selected period (automatic recent 15-minute test window)'),
                           ('before-restart', 'Before restart')):
            key = 'investigate.'+scope+'.'+mode
            if take(lambda r:r['key']==key and r['state']=='PASS'):
                worked.append(name+': requested '+scope+' journal queries were readable; incident detection still depends on usable evidence.')
            gaps = take(lambda r:r['key'].startswith(key+'.') and r['state'] in {'MISSING','SKIP'})
            if select_state(key, 'MISSING'):
                take(lambda r:r['key']==key and r['state']=='MISSING')
                unavailable.append(name+' ('+scope+'): journal investigation unavailable; no absence of faults can be established.')
            elif gaps:
                unavailable.append(name+' ('+scope+'): some sources or usable incident records were missing. Readable empty queries do not verify incident detection; see --details.')
    for kind,name in (('processes','Current process CPU/memory samples'),('filesystems','Filesystem space/inode samples')):
        key='resources.'+kind
        if take(lambda r:r['key']==key and r['state']=='PASS'):
            worked.append(name+' were read within the declared source bounds.')
        if take(lambda r:r['key']==key and r['state']=='MISSING'):
            unavailable.append(name+' could not be assessed; no zero or healthy result was inferred.')
    if take(lambda r:r['key']=='sessions.source' and r['state']=='PASS'):
        worked.append('The logged-in session source was readable; this does not verify completeness or user activity.')
    take(lambda r:r['state']=='PASS')  # Other successful details remain in --details/--json.

    defaults=take(lambda r:r['state']=='MISSING' and r['key'].startswith('health.journal.config.')
                  and 'No explicit assignment observed' in r['advice'])
    if defaults:
        unavailable.append('No explicit values were found for '+str(len(defaults))+' journald settings. Defaults may apply, but their effective values were not verified. This alone does not call for a configuration change.')

    blocked=select_state('history.system','MISSING') or select_state('diagnose.system','MISSING')
    if blocked:
        take(lambda r:r['state']=='MISSING' and (r['key'].startswith('history.system') or
             r['key'].startswith('diagnose.system')) and not r['key'].endswith(('.atop','.traffic_baseline')))
        unavailable.append('System-wide journal evidence could not be read in this run. Existing access or journal availability may be the reason; the result does not establish which.')
        actions.append('Optional: if system-wide evidence is needed and your ordinary user lacks access, rerun --live-only from an already authorized administrator terminal. If it still fails, inspect journal availability.')
    for scope in ('visible','system'):
        for source,name in (('ssh_analysis','SSH authentication'),('firewall_analysis','firewall')):
            key='diagnose.'+scope+'.'+source
            missing=take(lambda r:r['state']=='MISSING' and r['key'].startswith(key+'.'))
            if missing:
                unavailable.append('The checked '+('accessible' if scope=='visible' else 'system')+' logs contained no usable '+name+' messages for a real-data detection test. This does not prove that no events occurred.')

    atop=take(lambda r:r['key'].endswith(('.atop','.traffic_baseline')) and r['state'] in {'SKIP','MISSING'})
    if atop:
        if all(r['state']=='SKIP' for r in atop):
            unavailable.append('Historical Atop replay was not requested.')
            actions.append('Optional: use --atop-date YYYYMMDD with an existing recording to include historical measurements.')
        else:
            unavailable.append('Requested historical replay or its traffic baseline could not be verified. Comparison needs six comparable contiguous samples; missing access, gaps or RESET can prevent it.')
            actions.append('For historical analysis, check the selected recording date, access and recorded coverage. Do not change recorder settings just to make the test pass.')
    crash=take(lambda r:r['key'].startswith('pstore') and r['state'] in {'SKIP','MISSING'})
    if crash:
        if all(r['state']=='SKIP' for r in crash):
            unavailable.append('Persistent crash-evidence readers were not requested.')
            actions.append('Optional: add --pstore to inspect the existing fixed crash-evidence sources.')
        else:
            unavailable.append('Some crash-evidence sources or records were unavailable or empty. This does not rule out a crash.')

    manual=take(lambda r:r['key']=='tui.manual_navigation' and r['state']=='SKIP')
    if manual:
        unavailable.append('Manual TUI navigation in your own terminal has not been verified by this script.')
        actions.append('Manual check: run .venv/bin/python bin/faultlens tui. Try Left/Right tabs, Up/Down rows, Enter, Esc, e, r, resizing, q and Ctrl-C.')
    skipped_repo=take(lambda r:r['key'] in REPO_NAMES and r['state']=='SKIP')
    if skipped_repo:
        unavailable.append(str(len(skipped_repo))+' automated test groups were skipped in this mode or user context.')
        actions.append('To include software tests, run without --live-only as the non-root checkout owner.')
    for item in take(lambda r:r['state'] in {'MISSING','SKIP'}):
        unavailable.append(label(item['key'])+': '+item['message'])
        if item['key'].startswith('health.dependency.') or item['key'] in REPO_NAMES or item['key']=='tui.textual':
            actions.append('Review the missing requirement for '+label(item['key']).lower()+'. Nothing was installed automatically.')
    if not attention and not any(r['state']=='MISSING' and (r['key'].startswith('health.dependency.') or r['key'] in REPO_NAMES or r['key']=='tui.textual') for r in rows):
        actions.insert(0,'No immediate installation or configuration change is indicated by these checks. The items below concern optional coverage or manual verification.')
    return worked,unavailable,list(dict.fromkeys(actions)),attention


def render_server(data,out,*,details=False):
    worked,unavailable,actions,attention=server_summary(data)
    print('Faultlens server test',file=out)
    if data.get('environment'):
        context=data['environment']; release=context['os_release']
        print('Test context: '+safe(release.get('id') or 'OS unknown')+' '+safe(release.get('version_id') or 'version unknown')+
              ' | Python '+safe(context['python'])+' | '+safe(context['architecture'])+
              ' | Textual '+safe(context['textual'] or 'unavailable'),file=out)
        print('Checkout revision at start: '+safe(context['checkout_revision'] or 'unavailable')+
              ' (local edits not verified).',file=out)
        terminal=context['terminal']
        print('Terminal: '+(str(terminal['columns'])+' columns x '+str(terminal['rows'])+' rows'
              if terminal['columns'] is not None and terminal['rows'] is not None else 'size unavailable')+
              '; interactive input/output: '+str(terminal['input_interactive'])+'/'+str(terminal['output_interactive'])+
              '. Actual SSH interaction remains a manual check.',file=out)
    if data['counts']['FAIL']:
        print('Some checks failed. Review the failures below.',file=out)
    elif data['counts']['WARN']:
        print('No check failures were reported. Some observations need review.',file=out)
    elif unavailable:
        print('No check failures were reported. Some features could not be verified with the available data.',file=out)
    else:
        print('The completed checks reported no failures.',file=out)
    section(out,'What worked',worked or ['No successful checks were reported.'])
    if attention:
        section(out,'Failures or observations to review',attention)
    section(out,'What could not be tested or verified',unavailable or ['No gaps were reported for the checks that ran.'])
    section(out,'What you may need to do',actions or ['No follow-up action is indicated by these check results.'])
    print('\nNo server configuration was changed. Passing checks do not prove a healthy or attack-free server.',file=out)
    print('Use --details for every check and failure excerpt, or --json for structured results.',file=out)
    if details:
        print('\nTechnical details',file=out)
        for item in data['checks']:
            print('['+item['state']+'] '+safe(item['key'])+': '+safe(item['message']),file=out)
            if item['advice']:
                print('  '+safe(item['advice']),file=out)
            if 'details' in item:
                print('  Failure excerpt (truncated='+str(item['details_truncated'])+'): '+safe(item['details']),file=out)
        print('Check counts: '+' | '.join(k+'='+str(v) for k,v in data['counts'].items()),file=out)
        for note in data['limitations']:
            print('Note: '+safe(note),file=out)


def render_runtime(data,out):
    if data.get('runtime',{}).get('bytecode_cache')=='private_checked_hash':
        print('Runtime: private source-checked bytecode prepared before fresh-process measurements. Preparation: '+
              format(data['runtime']['preparation_wall_seconds'],'.3f')+' s; included in the overall test deadline.',file=out)


def render_benchmark(data,out,*,details=False):
    values=data['commands']
    failed=[name for name,v in values.items() if not v['within_regression_budget']]
    print('Faultlens performance tests',file=out)
    render_runtime(data,out)
    print(str(len(values))+' command scenarios tested; '+str(len(failed))+' outside the resource budgets.',file=out)
    if values:
        print('Largest peak memory: '+format(max(v['peak_rss_max_mib'] for v in values.values()),'.2f')+' MiB.',file=out)
        print('Slowest run: '+format(max(v['startup_wall_max_seconds'] for v in values.values()),'.3f')+' s (budget: below 2 s).',file=out)
    if failed:
        section(out,'Modes to investigate',[name.replace('-',' ') for name in failed])
    print('Memory budgets: CLI below 50 MiB; optional Textual workspace below 80 MiB. CPU below 1 s; wall below 2 s.',file=out)
    print('Synthetic data only. These results do not certify real server workload or storage latency.',file=out)
    if details:
        print('\nMode                           Peak MiB  Max wall s  Median CPU s  Result',file=out)
        for name,v in values.items():
            print(f"{safe(name):30} {v['peak_rss_max_mib']:8.2f} {v['startup_wall_max_seconds']:11.3f} {v['cpu_median_seconds']:13.3f}  "+('PASS' if v['within_regression_budget'] else 'FAIL'),file=out)
    else:
        print('Use --details for the per-mode table or --json for all measurements.',file=out)


def render_profiles(data,out,*,details=False):
    profiles=data['profiles']
    failed=[p for p in profiles if not p['passed']]
    print('Faultlens constrained resource tests',file=out)
    render_runtime(data,out)
    print(str(len(profiles))+' test runs; '+str(len(failed))+' failed the checks.',file=out)
    print('Each child uses one CPU and a virtual address-space limit. This is not a real small-VPS deployment test.',file=out)
    if failed:
        section(out,'Runs to investigate',[p['mode'].replace('-',' ')+' at '+str(p.get('address_space_limit_mib',p.get('memory_mib')))+' MiB: '+p.get('reason','resource budget exceeded') for p in failed])
    if details:
        print('\nMode                     Address limit MiB  Peak MiB  Wall s  Result',file=out)
        for p in profiles:
            print(f"{safe(p['mode']):24} {p.get('address_space_limit_mib',p.get('memory_mib')):17} "+
                (f"{p['peak_rss_mib']:9.2f} {p['wall_seconds']:7.3f}" if 'peak_rss_mib' in p else '      n/a     n/a')+
                ('  PASS' if p['passed'] else '  FAIL'),file=out)
    else:
        print('Use --details for each run or --json for all measurements.',file=out)


def render_comparison(data,out,*,details=False):
    rows=data['comparisons']
    counts={state:sum(r['state']==state for r in rows) for state in ('pass','mismatch','unavailable')}
    print('Faultlens measurement comparison',file=out)
    print(f"{counts['pass']} matched; {counts['mismatch']} differed; {counts['unavailable']} could not be compared.",file=out)
    for value in rows:
        description={'pass':'matched within tolerance','mismatch':'different; review collection timing and tolerances',
                     'unavailable':'not checked; measurement or reference unavailable'}[value['state']]
        print('  '+safe(METRIC_NAMES.get(value['key'],value['key']))+': '+description,file=out)
    print('Changing system load can affect comparisons. A match does not prove overall host health.',file=out)
    if details:
        for value in rows:
            print(safe(value['key'])+': '+value['state'].upper(),file=out)
        for text in data['limitations']:
            print('Note: '+safe(text),file=out)
    else:
        print('Use --details for metric IDs and limitations, or --json for structured results.',file=out)
