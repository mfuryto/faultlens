"""Explain existing observations without collecting, changing confidence or copying evidence."""
from datetime import datetime, timezone
import json
import re
import textwrap

NAMES = {'cpu.busy':'CPU activity', 'cpu.load_average':'System load', 'memory.total':'Total RAM',
    'memory.used':'RAM in use', 'swap.total':'Total swap', 'swap.used':'Swap in use',
    'system.uptime':'Uptime', 'system.boot_time':'Reported boot time', 'system.kernel_release':'Kernel version',
    'filesystem.root.total':'Root filesystem size', 'filesystem.root.available':'Available root filesystem space',
    'filesystem.root.used':'Root filesystem usage', 'filesystem.root.user_used':'Filesystem usage for ordinary users',
    'storage.io_counters':'Recorded disk counters', 'network.counters':'Recorded interface counters',
    'processes.visible':'Visible processes', 'services.system_state':'System service manager',
    'journal.previous_boots':'Accessible previous boots', 'journal.service_active':'Journal service',
    'atop.service_active':'Atop recorder service', 'journal.persistent_directory':'Persistent journal directory',
    'journal.runtime_directory':'Runtime journal directory', 'kernel.pstore_directory':'Crash-evidence directory',
    'network.interfaces':'Interface traffic rates',
    'journal.config.storage':'Journal storage mode', 'journal.config.system_max_use':'Persistent journal size limit',
    'journal.config.system_keep_free':'Free-space reserve for persistent journals',
    'journal.config.runtime_max_use':'Runtime journal size limit', 'journal.config.runtime_keep_free':'Free-space reserve for runtime journals',
    'journal.config.max_retention':'Journal retention setting', 'atop.config.interval':'Atop interval hint from defaults file',
    'atop.config.generations':'Atop retention hint', 'atop.config.standard_path':'Atop defaults-file path hint',
    'atop.recording_inventory':'Recording-file inventory', 'journal.storage.total':'Journal filesystem size',
    'journal.storage.available':'Available journal storage', 'atop.storage.total':'Recorder filesystem size',
    'atop.storage.available':'Available recorder storage'}
COUNTER_NAMES={'SyncookiesSent':'SYN cookies sent','SyncookiesRecv':'SYN cookies received',
    'SyncookiesFailed':'Invalid SYN cookies','ListenOverflows':'TCP listener overflows','ListenDrops':'TCP listener drops',
    'InDatagrams':'UDP datagrams received','OutDatagrams':'UDP datagrams sent','NoPorts':'UDP traffic without a listener',
    'InErrors':'UDP input errors','RcvbufErrors':'UDP receive-buffer errors','SndbufErrors':'UDP send-buffer errors'}
RULE_MEANINGS={
    'kernel.oom':'The kernel reported killing a process because of a memory shortage or limit. This can explain that process stopping; it does not establish why memory ran out or why the whole host stopped responding.',
    'kernel.panic':'The kernel reported a panic, a serious condition that can stop normal operation. The message alone does not identify its cause.',
    'kernel.io_error':'A storage operation was reported as failing. The device, virtual storage, driver and backing infrastructure all need consideration; physical disk failure is not established.',
    'kernel.filesystem_error':'The kernel reported a filesystem problem. Review storage and filesystem evidence before considering repair; a repair command is not automatically safe.',
    'kernel.overlay_layer_reuse':'The kernel warned that overlay mounts reused an upper/work directory. Review the mount/container setup; this does not prove data loss or explain a freeze by itself.',
    'kernel.soft_lockup':'A watchdog reported that a CPU was stuck too long. Scheduling, kernel and workload evidence are needed to understand why.',
    'kernel.hard_lockup':'A watchdog reported a CPU lockup. This is a recorded detector report, not proof of a hardware failure.',
    'kernel.hung_task':'A task was reported as blocked for a long time. Storage waits, filesystem problems or other kernel waits may be relevant; the cause is not identified.',
    'journal.messages_suppressed':'The journal reported suppressing messages. Missing records can limit reconstruction; their contents and exact coverage are unknown.',
    'journal.kernel_messages_missed':'The journal reported missed kernel messages. This confirms a loss report, not the contents or importance of the missing messages.',
    'systemd.start_job_failed':'The service manager reported that a unit failed to start. Inspect that unit and its nearby logs before changing service configuration.',
    'systemd.shutdown_marker':'A shutdown request was recorded. This shows shutdown started, not that shutdown completed normally.',
    'ssh.password_failed':'SSH reported a rejected password. One rejected login does not establish password guessing or malicious intent.',
    'ssh.password_accepted':'SSH reported accepting a password. This alone does not establish an authorized complete session or a compromise.',
    'ssh.invalid_user_report':'SSH reported a username that was not recognized. It may describe the same connection as another authentication report.',
    'firewall.ufw_packet_report':'A kernel message contains a supported firewall label and packet fields. A logging label does not verify the final packet verdict or prove an attack.',
    'security.ssh_failure_burst':'Repeated failed-password reports from one reported peer met the five-minute heuristic. Password guessing is possible, but typos, automation, proxies and duplicate reports can resemble it.',
    'security.port_scan_indicator':'Reports addressed several destination ports within a short window. This can resemble port probing, but legitimate scans or applications can produce the same pattern.',
    'security.udp_report_burst':'Many UDP-labelled log reports occurred close together. Logging duplication and rate limits prevent treating this as a measured packet rate or confirmed UDP flood.',
    'security.historical_traffic_anomaly':'A recorded network rate rose above its short local baseline. A workload change may be legitimate; this is not proof of a flood, attack or incident cause.',
}

# Fixed local read-only suggestions. Never interpolate source-controlled text into commands.
OBSERVATION_COMMANDS={
    'cpu.busy':'./bin/faultlens status --details',
    'cpu.load_average':'./bin/faultlens status --details',
    'memory.used':'./bin/faultlens status --details',
    'swap.used':'./bin/faultlens status --details',
    'services.system_state':'systemctl --failed --no-pager',
    'journal.service_active':'systemctl status systemd-journald.service --no-pager',
    'atop.service_active':'systemctl status atop.service --no-pager',
    'atop.recording_inventory':'./bin/faultlens health --history --details',
}
FINDING_COMMANDS={
    'kernel.overlay_layer_reuse':'findmnt --json --list -t overlay -o TARGET,OPTIONS',
    'systemd.start_job_failed':'systemctl --failed --no-pager',
    'network.': './bin/faultlens network --sockets --details',
    'security.port_scan_indicator':'./bin/faultlens network --sockets --details',
    'security.udp_report_burst':'./bin/faultlens network --sockets --details',
}


def observation_command(key):
    if key.startswith('filesystem.'): return 'df --block-size=1 --output=size,used,avail,pcent,target /'
    if key.startswith('journal.config.'): return 'systemd-analyze cat-config systemd/journald.conf'
    return OBSERVATION_COMMANDS.get(key)


def command_step(command):
    return 'Optional current-state check (not historical proof): '+command


def escaped(value):
    return json.dumps(str(value),ensure_ascii=True)[1:-1]


def name(item):
    key=item['key']
    if key in NAMES: return NAMES[key]
    if key.startswith('dependency.'): return 'Tool: '+key.removeprefix('dependency.')
    if key.startswith(('network.tcp.','network.udp.')): return COUNTER_NAMES.get(key.rsplit('.',1)[1],key)
    return key.replace('_',' ').replace('.',' / ').capitalize()


def size(value):
    for unit in ('B','KiB','MiB','GiB','TiB'):
        if abs(value)<1024 or unit=='TiB': return f'{value:.1f} {unit}'
        value/=1024


def duration(value):
    if value>=86400: return f'{value/86400:.1f} days'
    if value>=3600: return f'{value/3600:.1f} hours'
    if value>=60: return f'{value/60:.1f} minutes'
    return f'{value:.2f} seconds'


def reading(item):
    value,key,unit=item['value'],item['key'],item['unit']
    if key.startswith('dependency.'): return 'Available' if value is True else 'No trusted executable found'
    if item['state']=='unavailable': return 'Could not be measured'
    if value is None: return 'Not verified'
    if type(value) is bool: return 'Found' if value else 'Not found'
    if key=='system.boot_time':
        try: return datetime.fromtimestamp(value,timezone.utc).isoformat()
        except (ValueError,OverflowError,OSError): return str(value)+' Unix seconds'
    if type(value) in (int,float):
        if unit=='bytes': return size(value)
        if unit=='percent': return f'{value:.2f}%'
        if unit=='seconds': return duration(value)
        return str(value)+(' '+unit if unit else '')
    if isinstance(value,list):
        if key=='cpu.load_average': return ', '.join(str(v) for v in value)+' (1, 5 and 15 minutes)'
        return str(len(value))+' recorded '+('row' if len(value)==1 else 'rows')+'; open details for individual measurements'
    if isinstance(value,dict):
        if 'delta' in value: return str(value['delta'])+' additional events in this sample'
        return 'Structured measurements available in details'
    return str(value)


def observation_view(item):
    key,value,state=item['key'],item['value'],item['state']
    steps=[]
    if key.startswith('dependency.') and state=='unavailable':
        meaning='No trusted executable was found for this feature; the tool may be absent or inaccessible.'
        steps=[item['explanation'],'Provide this tool only if you need its feature; other observations can remain useful.']
    elif state=='unavailable':
        meaning='This source was missing, inaccessible, unsupported or outside its safe limits. It is not evidence that the host is healthy or broken.'
        steps=['Check this feature\'s existing tool, access and source availability. Other observations can still be useful.']
    elif value is None:
        meaning='A value could not be established. An unspecified configuration may use defaults; no effective default is guessed.'
        steps=['Do not change configuration just because this value is unverified. Compare existing settings and retained evidence if this feature matters.']
    elif key=='cpu.busy':
        meaning='CPU activity during a short sample. One sample does not show sustained overload or identify a busy process.'
        steps=['Repeat during the problem and compare load and process history if performance is poor.']
    elif key=='cpu.load_average':
        meaning='Average runnable/uninterruptible task counts, not CPU percentages. Interpretation depends on available CPUs and workload.'
        steps=['Compare with CPU availability, I/O waits and the time of the problem before diagnosing overload.']
    elif key.startswith(('memory.','swap.')):
        meaning='Current memory or swap accounting. Swap use or high memory use alone does not prove current pressure or an OOM event.'
        steps=['If memory problems are reported, compare process usage, limits, swap activity and recorded OOM events.'] if state in {'warning','critical'} else []
    elif key.startswith('filesystem.'):
        meaning='Space on the root filesystem, not a disk-integrity check. Ordinary users may have less usable space because some blocks are reserved.'
        steps=['Review space consumers and retention safely before deleting anything or changing storage limits.'] if state in {'warning','critical'} else []
    elif key.startswith('dependency.'):
        meaning='The tool was found in a trusted executable location. This does not verify its version, service state or access to data.'
    elif key in {'journal.service_active','atop.service_active'}:
        meaning='Reported service state only. An active recorder does not prove useful history, correct sampling or retention.'
        steps=['Review the existing service and recording setup locally if this feature is unavailable or inactive.'] if value!='active' else []
    elif key=='services.system_state':
        meaning='The service manager reports '+str(value)+'. This is a manager summary, not an assessment of every service.'
        steps=['Inspect the affected service units and their logs before considering changes.'] if state!='normal' else []
    elif key.endswith('_directory'):
        meaning='Directory presence only. It does not prove retained journal history, a working crash backend or complete access.'
    elif key.startswith(('network.tcp.','network.udp.')):
        meaning='Change in a kernel protocol counter between two samples. Counters can overlap; growth does not identify an attacker or prove a flood.'
        steps=['Compare expected load, application behavior and resource limits when error/pressure counters grow.'] if isinstance(value,dict) and value.get('delta',0)>0 else []
    elif key=='network.interfaces':
        meaning='Two local interface snapshots estimate traffic rates. Resets and changed interfaces prevent comparisons; virtual layers may count the same traffic more than once.'
    elif key in {'network.counters','storage.io_counters'}:
        meaning='Accumulated counters, not current transfer speeds or proof that a device is healthy. Do not sum overlapping virtual devices.'
    elif key=='journal.config.storage':
        if value=='volatile':
            meaning='The configuration asks for runtime-only journal storage, which may not survive a reboot. The effective loaded setting is not verified.'
        elif value=='none':
            meaning='The configuration asks to disable journal storage. This does not verify the running setting or prove existing history is absent.'
        else:
            meaning='A storage-mode assignment was found, but the loaded setting, retained history and actual access still need verification.'
    elif key=='atop.recording_inventory':
        meaning='This is a bounded filename/size inventory. Filenames do not prove that recordings are complete or usable.'
        steps=['Verify that the desired recording can be replayed; review reported file gaps and access before relying on the history.']
    elif key=='journal.previous_boots':
        meaning='Previous boots visible with current permissions and retention. Missing history does not prove a boot or crash did not occur.'
    else:
        meaning=item.get('explanation','A local observation, not a diagnosis of cause.')
    if not steps: steps=list(item.get('recommendations',[]))
    if not steps: steps=['No change is indicated by this reading alone. Investigate further if symptoms or other evidence call for it.']
    if state in {'warning','critical','unavailable'} or value is None:
        command=observation_command(key)
        if command: steps.append(command_step(command))
    return {'Observed':reading(item),'What it means':meaning,'What you can do':steps,
            'Confidence':item['confidence'],'Evidence limits':list(item.get('limitations',[])),'Technical details':item}


def finding_view(item):
    rule=item['rule_id']
    meaning=RULE_MEANINGS.get(rule)
    if meaning is None and rule.startswith('network.'):
        meaning='A supported kernel counter increased. Legitimate load, resource limits and network settings can produce this; it is not a confirmed attack or outage.'
    if meaning is None:
        meaning=item['observation']+' The source report does not establish the underlying cause.'
    steps=list(item['recommendations'])
    command=FINDING_COMMANDS.get(rule)
    if command is None and rule.startswith('network.'): command=FINDING_COMMANDS['network.']
    if command: steps.append(command_step(command))
    return {'Observed':item['observation'],'What it means':meaning,
        'Confidence':item['confidence']+' observation; cause '+item.get('cause_confidence','Unknown'),
        'What you can do':steps,'Evidence limits':list(item['limitations']),
        'Technical details':item}


def finding_groups(data):
    """Use only normalized finding locations, never arbitrary original message objects."""
    groups={}
    sources=[('main',data.get('findings',[]))]
    for key in ('security_analysis','ssh_analysis','firewall_analysis'):
        sources.append((key,data.get(key,{}).get('findings',[])))
    for query in data.get('event_search',{}).get('queries',[]):
        sources.append(('event_search.'+query['query'],query['findings']))
    for source,values in sources:
        for item in values:
            identity=(source,item['rule_id'],item['confidence'],item['severity'])
            if identity not in groups: groups[identity]=[item,0,source]
            groups[identity][1]+=1
    return list(groups.values())


def boot_summary_label(item):
    prefix='Boot '+str(item['boot']['index'])+' | '
    if item['state']!='available': return prefix+'Journal evidence unavailable'
    count,records=item['finding_count'],item['records_examined']
    return (prefix+str(count)+' matched report'+('s' if count!=1 else '')+' in '+str(records)
            +' retained record'+('s' if records!=1 else ''))


def boot_summary_view(item):
    """Explain one retained boot summary without guessing incident count or causality."""
    meaning=[]
    if item['state']!='available':
        meaning.append('No usable journal tail was retained for this boot. This does not establish absent logs, permission denial or a crash.')
    elif item['finding_count']:
        meaning.append('These counts describe matched source reports, not separate incidents, verified root causes or complete shutdown outcomes.')
        for rule,count in sorted(item['finding_counts_by_rule'].items()):
            explanation=RULE_MEANINGS.get(rule,'Recorded rule '+rule).split('. ',1)[0]
            meaning.append(str(count)+' report'+('s' if count!=1 else '')+': '+explanation)
    else:
        meaning.append('No supported pattern matched this retained tail. A crash, freeze or earlier problem is not ruled out.')
    limits=['A bounded tail is not a complete boot; first/last visible records are not boot or incident boundaries.',
            'Root cause and complete shutdown remain unverified. Different boots do not form a shared monotonic timeline.',
            'This overview excludes broader event searches, SSH/firewall searches, Atop replay and crash-evidence readers.']
    if item['record_limit_reached']: limits.append('The retained-record cap was reached; earlier entries may be omitted.')
    if item['unsupported_messages_in_response']:
        limits.append(str(item['unsupported_messages_in_response'])+' message bodies could not be classified; no absence of events is inferred.')
    boot_id=item['boot']['boot_id']
    scope=item['journal_scope']['requested']
    steps=['Inspect the original summary and its collection limits before drawing conclusions.']
    if isinstance(boot_id,str) and re.fullmatch(r'[a-f0-9]{32}',boot_id) and scope in {'visible','system'}:
        command='./bin/faultlens diagnose --boot-id '+boot_id+(' --system-journal' if scope=='system' else '')
        steps.append('Optional fresh diagnosis using this boot identity and existing access: '+command)
    return {'Observed':boot_summary_label(item),'Boot identity':boot_id,'What it means':meaning,
            'What you can do':steps,'Evidence limits':limits,'Technical details':item}


def guide(data):
    observations=data.get('observations',[])
    warning=sum(o['state'] in {'warning','critical'} for o in observations)
    missing=sum(o['state']=='unavailable' or o['value'] is None for o in observations)
    groups=finding_groups(data)
    meaning,actions,limits=[],[],[]
    crash_warning=any(record['panic_signature_lines'] for key in ('pstore','pstore_archive') for record in data.get(key,{}).get('records',[]))
    source_gap=any(data.get(key,{}).get('state') in {'unavailable','partial'} for key in ('atop','ssh_analysis','firewall_analysis','event_search','pstore','pstore_archive'))
    source_gap |= data.get('unsupported_messages',0)>0
    source_gap |= any(item['unsupported_messages_in_response'] for item in data.get('summaries',[]))
    source_gap |= any(data.get(key,{}).get('analysis_state') in {'unavailable','partial'} for key in ('pstore','pstore_archive'))
    boot_reports=any(item['finding_count'] for item in data.get('summaries',[]))
    if warning or crash_warning or boot_reports or any(item['severity'] in {'warning','critical'} for item,count,source in groups):
        summary='Some observations or recorded reports need review. Their meaning and next steps are listed below.'
    elif data.get('state')=='unavailable':
        summary='The main evidence source was unavailable. Independently available source results are explained below; what happened remains unverified.'
    elif data.get('state')=='partial' or source_gap or missing:
        summary='Some evidence was collected, but other parts could not be verified. Review the coverage limits before drawing conclusions.'
    else:
        summary='Readings were collected without a matched warning in the checked data. This is not a complete health or security verdict.'
    if data['command']=='status':
        meaning.append('These are current local readings. A short sample cannot reconstruct earlier overload or a freeze.')
        if any(item['key']=='cpu.load_average' and item['value'] is not None for item in observations):
            meaning.append('System load counts runnable/waiting tasks; it is not a CPU-usage percentage.')
        if any(item['key']=='swap.used' and type(item['value']) in (int,float) and item['value']>0 for item in observations):
            meaning.append('Some swap is in use. Swap use alone does not establish current memory pressure.')
    if data['command'] in {'check','health'}:
        meaning.append('Tool discovery and service activity are basic checks; they do not prove that useful history is being recorded.')
    if missing:
        meaning.append(str(missing)+' observation values are unavailable or unverified; this is not automatically a program or server failure.')
    defaults=[o for o in observations if o['value'] is None and o['key'].startswith('journal.config.') and 'No explicit assignment' in o.get('explanation','')]
    if defaults:
        meaning.append('Some journald settings have no explicit assignment. Defaults may apply; effective settings were not verified. This alone does not require reconfiguration.')
    if data['command'] in {'history','diagnose','incidents'}:
        scope=data.get('journal_scope',{}).get('requested','visible')
        meaning.append('Only accessible '+scope+' journal evidence was requested; selection grants no extra permission and does not prove completeness.')
        if data.get('state')=='unavailable':
            actions.append('Check the selected boot, existing journal access and retained history. The failure alone does not prove permission denial or absent history.')
            command='journalctl '+('--system ' if scope=='system' else '')+'--list-boots --no-pager'
            actions.append('To see the journal tool\'s own access/availability explanation, run: '+command)
            actions.append('Use existing authorized access only. This command grants no permissions; an empty listing does not prove that no earlier boot occurred.')
        if data['command']=='history':
            meaning.append(str(len(data.get('boots',[])))+' boot entries are visible in the bounded listing.' if data['state']=='available' else 'No boot listing could be verified; this is not evidence that earlier boots are absent.')
        if data['command']=='incidents':
            meaning.append(str(data.get('selected_boot_count',0))+' boots were selected for summaries. Finding counts are reports, not separate incidents.')
            if data.get('selection_limit_reached'):
                meaning.append('More eligible boots were visible than requested; the remaining boots were not examined in this overview.')
            actions.append('Select a listed boot ID for a detailed diagnosis if you want to investigate that boot.')
        if data['command']=='diagnose':
            meaning.append('Retained journal records examined: '+str(data['records_examined'])+'. Root cause and complete shutdown remain unverified.')
            chronology=data.get('reconstruction')
            if chronology and chronology['state']=='available':
                meaning.append('Retained records span '+duration(chronology['monotonic_span_us']/1000000)+'. Intervals without records do not prove downtime, lost logging or a freeze.')
                if chronology['clock_mapping']['assessment']=='variable':
                    meaning.append('The wall-clock mapping varied. Use the recorded boot-local order cautiously; the reason for the change is not established.')
            if data.get('unsupported_messages',0):
                meaning.append(str(data['unsupported_messages'])+' message bodies could not be classified. Their original representations remain available when requested.')
            if data.get('record_limit_reached'):
                meaning.append('The retained-record limit was reached; earlier entries may be omitted.')
            if data.get('selected_boot'):
                selected=data['selected_boot']
                meaning.append('Selected boot '+str(selected['index'])+' (ID '+selected['boot_id']+').')
            if data.get('journal_window',{}).get('mode')!='tail':
                meaning.append('Receipt-time bounds restrict this query; log receipt time is not necessarily the event time.')
            if not groups: meaning.append('No supported journal pattern matched the checked journal evidence. This does not rule out a crash, attack or freeze.')
    for key,description in (('ssh_analysis','SSH authentication'),('firewall_analysis','firewall logging')):
        source=data.get(key)
        if source:
            if source['state']!='available': meaning.append(description+' evidence was unavailable in this scope; absence of events is not established.')
            elif not source['findings']: meaning.append('No supported '+description+' pattern matched these checked records; unclassified originals remain in technical evidence.')
    if 'atop' in data:
        atop=data['atop']
        if atop['state']=='not_requested': meaning.append('Historical resource replay was not requested.')
        elif atop['state']!='available': meaning.append('The requested recording could not provide usable measurements; check the date, access and replay window.')
        else: meaning.append(str(len(atop['samples']))+' recorded resource samples were read; recording host/boot identity remains unverified.')
    target=data.get('event_search')
    if target:
        meaning.append('Broader journal event search: '+target['state']+'. Query results are limited to their selected sources and retained candidates.')
        if target['state']!='available': actions.append('Inspect individual search coverage in details before drawing conclusions about unmatched events.')
    security=data.get('security_analysis',{})
    if security.get('findings_truncated'):
        meaning.append('The security finding list was capped; '+str(security['matching_indicators'])+' indicators matched the rules. Remaining source evidence is available within its original collection limits.')
    if security.get('historical_comparison',{}).get('state')=='insufficient_comparable_history' and data.get('atop',{}).get('state')=='available':
        meaning.append('Historical traffic comparison needs six comparable consecutive samples. The available evidence did not provide that baseline.')
    for key in ('pstore','pstore_archive'):
        source=data.get(key)
        if source:
            meaning.append('Crash evidence: '+str(len(source['records']))+' records reported by '+source['source']+'; state '+source['state']+'. Records are not attributed to the selected boot.')
            matching=sum(bool(record['panic_signature_lines']) for record in source['records'])
            if matching:
                meaning.append(str(matching)+' crash record fragments match a panic signature (Possible). Their authenticity, cause and boot identity remain unverified; duplicate fragments are not independent incidents.')
                actions.append('Inspect original crash fragments and compare nearby recorded kernel events before attributing them to a boot or cause.')
            if source['analysis_state'] in {'unavailable','partial'}:
                meaning.append('Crash content could not be fully checked for supported signatures; readable source data is not the same as complete analysis.')
            limits.append('An empty or unavailable crash archive does not rule out a crash.')
    if data['command'] in {'network','security'}:
        elapsed=data['sample']['elapsed_seconds']
        if elapsed is not None: meaning.append('Measured sampling interval: '+duration(elapsed)+'. Reads are sequential, not atomic.')
        meaning.append('Traffic and protocol counters cover the current network namespace and a short sample, not all host traffic or a sustained attack baseline.')
        if data.get('sockets',{}).get('state')=='available': meaning.append('Socket bindings are visible locally; listening or wildcard addresses do not prove access from the Internet.')
        actions.append('Compare changes during the reported problem with expected workload and service capacity before considering network or firewall changes.')
    if not actions: actions.append('No configuration change follows from these readings alone. Review explained warnings and relevant source evidence if investigating a symptom.')
    limits.append('Suggested commands are optional and never run automatically. Use a trusted checkout/tool installation and existing access; missing optional tools do not require installation. Current snapshots cannot establish past incident conditions.')
    limits.append('Readable sizes and durations are rounded; exact values and thresholds remain in technical details.')
    limits.append('Local logs and counters can be incomplete or falsified; authenticity is not established, particularly under root/kernel compromise.')
    limits.append('Source coverage is bounded and local. A confirmed report is not a confirmed cause; possible security indicators are not confirmed attacks.')
    return {'Summary':summary,'What the evidence means':meaning,'What you can do':actions,'Important limits':limits}


def timeline_label(position):
    rule=position['rule_id']
    title=RULE_MEANINGS.get(rule,rule).split('. ',1)[0]
    unresolved='Order unresolved at equal timestamps | ' if position['relative_order']=='unresolved_equal_timestamp' else ''
    return unresolved+duration(position['from_first_visible_record_us']/1000000)+' after first retained record | '+title


def line(out,text,indent=''):
    for value in textwrap.wrap(escaped(text),width=96,initial_indent=indent,subsequent_indent=' '*len(indent)+'  ') or [indent]:
        print(value,file=out)


def advice_line(out,text,indent='',prefix=''):
    """Keep suggested commands on one escaped physical line for reliable copying."""
    markers=('Optional current-state check (not historical proof): ',
             'Optional fresh diagnosis using this boot identity and existing access: ',
             'To see the journal tool\'s own access/availability explanation, run: ')
    for marker in markers:
        if text.startswith(marker):
            line(out,prefix+marker.rstrip(),indent)
            print(' '*(len(indent)+2)+escaped(text[len(marker):]),file=out)
            return
    line(out,prefix+text,indent)


def render(data,out):
    view=guide(data)
    print('Faultlens - '+data['command'].capitalize()+' (read-only)',file=out)
    line(out,view['Summary'])
    if data.get('observations'):
        print('\nCurrent readings',file=out)
        for item in data['observations']:
            detail=observation_view(item)
            marker={'warning':'Needs review','critical':'High-priority reading','unavailable':'Unavailable'}.get(item['state'],'Unverified' if item['value'] is None else '')
            line(out,name(item)+': '+detail['Observed']+(' ['+marker+']' if marker else ''), '  ')
            unspecified=item['value'] is None and item['key'].startswith('journal.config.') and 'No explicit assignment' in item.get('explanation','')
            if not unspecified and (item['state'] in {'warning','critical','unavailable'} or item['value'] is None):
                line(out,'Meaning: '+detail['What it means'],'    ')
                for step in detail['What you can do']: advice_line(out,step,'    ','Next: ')
    for item in data.get('observations',[]):
        if item['key']=='network.interfaces' and isinstance(item['value'],list):
            from .interface_presentation import interface_view
            for interface in item['value']:
                detail=interface_view(interface,data['sample'])
                line(out,detail['Observed'],'  ')
                for text in detail['Measurements'][:2]: line(out,text,'    ')
                if interface['delta'] is not None:
                    for text,key in zip(detail['Measurements'][2:],('receive_errors','receive_drops','send_errors','send_drops')):
                        if interface['delta'][key]>0: line(out,text,'    ')
                if interface['state']!='compared': line(out,detail['What it means'],'    ')
    groups=finding_groups(data)
    if groups:
        print('\nExplained findings',file=out)
        for item,count,source in groups:
            explanation=finding_view(item)
            location={'main':'current counter sample' if data['command'] in {'network','security'} else 'selected journal tail',
                'security_analysis':'derived security indicators','ssh_analysis':'SSH event search',
                'firewall_analysis':'firewall event search'}.get(source,source.replace('_',' '))
            line(out,item['title']+' | '+explanation['Confidence']+' | '+str(count)+' matching finding'+('s' if count!=1 else '')+' | '+location,'  ')
            line(out,'Observed: '+explanation['Observed'],'    ')
            line(out,explanation['What it means'],'    ')
            for step in explanation['What you can do']: advice_line(out,step,'    ','Next: ')
        line(out,'Report counts can overlap and do not establish separate incidents or independent corroboration.')
    if data.get('summaries'):
        print('\nBoot summaries',file=out)
        for item in data['summaries']:
            detail=boot_summary_view(item)
            line(out,detail['Observed'],'  ')
            line(out,'Boot ID: '+detail['Boot identity'],'    ')
            for text in detail['What it means']: line(out,text,'    ')
            for step in detail['What you can do']: advice_line(out,step,'    ','Next: ')
            for text in detail['Evidence limits']: line(out,'Limit: '+text,'    ')
    if data.get('atop',{}).get('state') not in {None,'not_requested'}:
        from .recording_presentation import recording_view,sample_label,sample_measurements
        source=data['atop']; detail=recording_view(source)
        print('\nRecorded resources',file=out)
        line(out,detail['Observed'],'  ')
        for text in detail['What it means']: line(out,text,'  ')
        for sample in source['samples']:
            line(out,sample_label(sample),'  ')
            line(out,'Recorded host: '+sample.get('recorded_hostname','Not retained'),'    ')
            line(out,'; '.join(sample_measurements(sample)),'    ')
        for text in detail['Evidence limits']: line(out,'Limit: '+text,'  ')
    for key in ('pstore','pstore_archive'):
        if key in data:
            from .crash_presentation import source_view,record_label,record_view
            source=data[key]; detail=source_view(source)
            print('\n'+('Live crash evidence' if key=='pstore' else 'Archived crash evidence'),file=out)
            line(out,detail['Observed'],'  ')
            for text in detail['What it means']: line(out,text,'  ')
            for record in source['records']:
                line(out,record_label(record)+' | analysis '+record['analysis_state']+' | encoding '+record['content']['encoding'],'  ')
                if record.get('relative_path') is not None: line(out,'Relative path: '+record['relative_path'],'    ')
                if record['analysis_state']!='available' or record['content']['encoding']=='base64':
                    for text in record_view(record)['What it means']: line(out,text,'    ')
            for text in detail['Evidence limits']: line(out,'Limit: '+text,'  ')
    for title in ('What the evidence means','What you can do','Important limits'):
        if view[title]:
            print('\n'+title,file=out)
            for text in view[title]: advice_line(out,text,'  - ')
    if data['command'] in {'history','incidents'}:
        for boot in data.get('boots',[]):
            line(out,'Boot '+str(boot['index'])+': '+boot['boot_id']+' (identity for detailed investigation)','  ')
    if 'sockets' in data:
        from .socket_presentation import snapshot_view,row_label,state_meaning,binding_meaning
        snapshot=data['sockets']
        detail=snapshot_view(snapshot)
        print('\nSocket snapshot',file=out)
        line(out,detail['Observed'],'  ')
        for text in detail['What it means']: line(out,text,'  ')
        for text in detail['What you can do']: line(out,'Next: '+text,'  ')
        explained=set()
        for value in snapshot['rows']:
            identity=(value['protocol'],value['state'])
            if identity not in explained:
                title,meaning=state_meaning(value)
                line(out,value['protocol'].upper()+' '+value['state']+': '+title+'. '+meaning,'  ')
                explained.add(identity)
            line(out,row_label(value)+' | '+binding_meaning(value)[0],'  ')
        line(out,'Queue values retain native semantics, not universal byte counts or pressure thresholds. Socket owners, application identity and external reachability were not collected.','  ')
    print('\nUse --details for technical measurements, references and limitations; --json for structured data.',file=out)
    print('Use diagnose --show-evidence when original journal/recording evidence is needed.',file=out)
