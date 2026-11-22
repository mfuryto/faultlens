"""Problem/time-centered investigations with bounded, boot-isolated evidence."""
import json
import math
import time
from collections import defaultdict

from .commands import Command, CommandRunner, Result
from .incidents import diagnose, history
from .journal import (BOOT_ID,MAX_BYTES,MAX_RECORDS,bounded_structure,entries,
                      reject_constant,unique_object,validate_window)
from .models import report

MODES=('now','period','before-restart')
MAX_SCOPES=7
RECENT_US=15*60*1000000
LIMITS=[
    'Current measurements describe collection time only; they do not establish conditions during an earlier incident.',
    'Journal receipt-time bounds apply to every requested query. Missing or unmatched records never prove absence of faults.',
    'Each query retains at most 500 records across all boots; at most seven boot partitions are interpreted. Coverage is not complete.',
    'Monotonic chronology is boot-local. Different boots are never combined into a causal timeline.',
    'Source authenticity and the underlying cause remain unverified. No elevation, configuration change or external report exposure occurs.',
]


def partition(result,since_us,until_us,boot_id=None):
    """Validate the entire captured response before exposing any boot partition."""
    meta={'command_state':result.state,'returncode':result.returncode,'state':'unavailable',
          'parse_state':'not_attempted','records_retained':0,'record_limit_reached':False}
    if result.state!='completed' or result.returncode!=0: return {},meta
    try:
        if len(result.stdout.encode('utf-8'))>MAX_BYTES: raise ValueError('Journal byte limit')
        lines=[line for line in result.stdout.splitlines() if line.strip()]
        if len(lines)>MAX_RECORDS+1: raise ValueError('Journal record limit')
        groups=defaultdict(list)
        for line in lines:
            item=json.loads(line,object_pairs_hook=unique_object,parse_constant=reject_constant)
            bounded_structure(item)
            identity=item.get('_BOOT_ID') if isinstance(item,dict) else None
            if not isinstance(identity,str) or not BOOT_ID.fullmatch(identity) or (boot_id is not None and identity!=boot_id):
                raise ValueError('Invalid boot scope')
            groups[identity].append(line)
        for identity,rows in groups.items():
            entries('\n'.join(rows),identity,validator=lambda entry:
                (since_us is None or entry.realtime_us>=since_us) and (until_us is None or entry.realtime_us<=until_us))
        # Drop a single global sentinel, not one per boot. Validate it before dropping.
        if len(lines)>MAX_RECORDS:
            first=lines[0];identity=json.loads(first)['_BOOT_ID'];groups[identity].pop(0)
        groups={identity:'\n'.join(rows) for identity,rows in groups.items() if rows}
        meta.update(state='available',parse_state='valid' if lines else 'empty',
                    records_retained=min(len(lines),MAX_RECORDS),record_limit_reached=len(lines)>MAX_RECORDS)
        return groups,meta
    except (ValueError,TypeError,UnicodeError,RecursionError):
        meta['parse_state']='invalid';return {},meta


class PartitionRunner:
    """Read only the already captured partition; no command/native fallback."""
    def __init__(self,identity,queries,coverage): self.identity,self.queries,self.coverage=identity,queries,coverage
    def run(self,command):
        if command not in {Command.JOURNAL_BOOTS,Command.JOURNAL_SYSTEM_BOOTS}: raise ValueError('Unexpected partition command')
        return Result('completed','0 '+self.identity+' retained-scope\n',0)
    def response(self,query):
        meta=self.coverage[query]
        if meta['state']!='available': return Result('unavailable')
        return Result('completed',self.queries[query].get(self.identity,''),0)
    def read_boot(self,identity): return self.response('tail')
    def read_system_boot(self,identity): return self.response('tail')
    def read_boot_window(self,identity,since_us,*,until_us=None,system=False): return self.response('tail')
    def read_boot_until(self,identity,until_us,*,system=False): return self.response('tail')
    def read_event_candidates(self,identity,query,**options): return self.response(query)
    def read_ssh_candidates(self,identity,**options): return self.response('ssh_events')
    def read_firewall_candidates(self,identity,**options): return self.response('firewall_events')


def collect(runner=None,*,sources=None,mode='now',boot_id=None,boot_index=None,since_us=None,until_us=None,
            system_journal=False,search_events=True,search_ssh=False,search_firewall=False,
            sample_seconds=.1,sockets=False,network_context=False,atop_date=None,atop_extended=False,
            pstore=False,pstore_archive=False,pstore_collector=None,pstore_archive_collector=None,clock=time.time):
    if type(sample_seconds) not in {int,float} or not math.isfinite(sample_seconds) or not .05<=sample_seconds<=1: raise ValueError('Invalid sample duration')
    if mode not in MODES: raise ValueError('Unknown investigation mode')
    validate_window(since_us,until_us)
    if boot_id is not None and (not isinstance(boot_id,str) or not BOOT_ID.fullmatch(boot_id)): raise ValueError('Invalid boot filter')
    if boot_index is not None and (type(boot_index) is not int or not -128<=boot_index<=0): raise ValueError('Invalid boot index')
    if mode=='before-restart' and boot_index==0: raise ValueError('Before-restart mode requires a previous boot')
    if boot_id is not None and boot_index is not None: raise ValueError('Conflicting boot filters')
    if any(type(v) is not bool for v in (system_journal,search_events,search_ssh,search_firewall,sockets,network_context,atop_extended,pstore,pstore_archive)):
        raise ValueError('Invalid investigation option')
    if atop_extended and not atop_date: raise ValueError('Recording date required')
    if network_context and mode!='now':raise ValueError('Current network context requires now mode')
    if mode=='period' and (since_us is None or until_us is None): raise ValueError('A selected period requires both time boundaries')
    if mode!='period' and (since_us is not None or until_us is not None): raise ValueError('Explicit boundaries require period mode')
    if mode=='now':
        until_us=int(clock()*1000000);since_us=max(0,until_us-RECENT_US);validate_window(since_us,until_us)
    if atop_date:
        from .recordings import recording_date
        recording_date(atop_date)
    runner=runner or CommandRunner()
    data=report('investigate',[])
    data.update(mode=mode,root_cause='Unknown',state='unavailable',current={},investigations=[],query_coverage={},
                journal_scope={'requested':'system' if system_journal else 'visible','completeness':'unknown'},
                requested_window={'since_realtime_us':since_us,'until_realtime_us':until_us},
                boot_filter={'requested':boot_id if boot_id is not None else boot_index,'resolved':boot_id,'resolved_index':None},
                scope_limit_reached=False,omitted_boot_scopes=0,uninterpreted_records={},selection_state='not_required')
    data['limitations']=list(LIMITS)
    data['current_snapshot_state']='requested' if mode=='now' else 'not_requested_for_historical_mode'
    if mode=='now':
        from .health import collect as health
        from .network import collect as network
        data['current']['health']=health(sources,runner,sample_seconds=sample_seconds)
        if network_context:
            from .network_sampling import practical
            data['current']['network']=practical(sources,runner,sample_seconds=sample_seconds,sockets=sockets)
        else:data['current']['network']=network(sources,sample_seconds=sample_seconds)
        if sockets and not network_context:
            from .sockets import attach
            attach(data['current']['network'],runner)
    if boot_index is not None or (mode=='before-restart' and boot_id is None):
        listing=history(runner,system_journal=system_journal)
        requested=boot_index if boot_index is not None else -1
        selected=next((boot for boot in listing['boots'] if boot['index']==requested),None)
        data['selection_state']='resolved' if selected else 'unavailable'
        data['boot_listing']=listing['boot_listing']
        if selected:
            boot_id=selected['boot_id'];data['boot_filter'].update(resolved=boot_id,resolved_index=selected['index'])
        else:
            data['limitations'].append('The requested previous boot/filter could not be resolved; no wider fallback query was run.')
    if data['selection_state']!='unavailable':
        queries=['tail']+(['kernel_warnings','systemd_events'] if search_events else [])
        if search_ssh: queries.append('ssh_events')
        if search_firewall: queries.append('firewall_events')
        captured={}
        for query in queries:
            result=runner.read_journal_window(since_us,until_us,boot_id=boot_id,
                query=None if query=='tail' else query,system=system_journal)
            captured[query],data['query_coverage'][query]=partition(result,since_us,until_us,boot_id)
        identities=set().union(*(set(value) for value in captured.values()))
        # Deterministic identity ordering; this is not a cross-boot event chronology.
        ordered=sorted(identities)
        data['scope_limit_reached']=len(ordered)>MAX_SCOPES
        data['omitted_boot_scopes']=max(0,len(ordered)-MAX_SCOPES)
        omitted=set(ordered[MAX_SCOPES:])
        data['uninterpreted_records']={query:{identity:text for identity,text in values.items() if identity in omitted}
            for query,values in captured.items() if any(identity in omitted for identity in values)}
        for identity in ordered[:MAX_SCOPES]:
            child=diagnose(PartitionRunner(identity,captured,data['query_coverage']),boot_id=identity,
                system_journal=system_journal,search_events=search_events,search_ssh=search_ssh,
                search_firewall=search_firewall,since_us=since_us,until_us=until_us,show_evidence=True)
            # The cache uses index 0 only to reuse the single-boot parser. No actual
            # relative index was discovered by a period query, so never expose it.
            index=data['boot_filter']['resolved_index'] if identity==data['boot_filter']['resolved'] else None
            child['selected_boot']['index']=index
            for boot in child['boots']: boot['index']=index
            child['global_query_coverage']=data['query_coverage']
            child['limitations'].append(('Relative boot index is unknown for this retained time-window partition.' if index is None else
                'Relative boot index comes from the selected listing snapshot.')+' Global query caps also apply.')
            child['inquiry_context']={'mode':mode,'requested_window':dict(data['requested_window']),
                'requested_boot_filter':data['boot_filter']['requested'],'resolved_boot_filter':boot_id,
                'journal_scope':data['journal_scope']['requested'],'source_role':'journal_partition'}
            data['investigations'].append(child)
        for child in data['investigations']:
            sources=[(row['query'],row) for row in child.get('event_search',{}).get('queries',[])]
            sources += [(query,child[key]) for query,key in (('ssh_events','ssh_analysis'),('firewall_events','firewall_analysis')) if key in child]
            for query,source in sources:
                if source['state']!='available' and data['query_coverage'][query]['state']=='available':
                    data['query_coverage'][query].update(state='partial',parse_state='source_validation_incomplete')
        states=[row['state']=='available' for row in data['query_coverage'].values()]
        data['state']='available' if all(states) and not data['scope_limit_reached'] else 'partial' if any(row['state'] in {'available','partial'} for row in data['query_coverage'].values()) else 'unavailable'
    if atop_date:
        if len(data['investigations'])==1:
            from .atop import attach
            attach(data['investigations'][0],atop_date,runner,extended=atop_extended)
            from .security_analysis import assess
            assess(data['investigations'][0])
        else:
            data['atop']={'state':'unavailable','reason':'select_one_retained_boot_for_optional_recording_correlation',
                          'samples':[],'correlations':[]}
    for requested,key,collector in ((pstore,'pstore',pstore_collector),(pstore_archive,'pstore_archive',pstore_archive_collector)):
        if requested:
            if key=='pstore':
                from .pstore import analyze
            else:
                from .pstore_archive import analyze
            data[key]=analyze(collector)
    data['optional_sources']={key:(data[key]['state'] if key in data else
        data['investigations'][0].get('atop',{}).get('state','unavailable') if key=='atop' and atop_date and len(data['investigations'])==1 else 'not_requested')
        for key in ('atop','pstore','pstore_archive')}
    for source in data['current'].values():
        source['inquiry_context']={'mode':mode,'requested_window':dict(data['requested_window']),
            'requested_boot_filter':data['boot_filter']['requested'],'resolved_boot_filter':boot_id,
            'journal_scope':data['journal_scope']['requested'],'source_role':'current_snapshot'}
    return data


def story(data):
    from .investigation import examples,utc
    faults=[(finding,child) for child in data['investigations'] for finding,count,source in examples(child)
            if finding['severity'] in {'warning','critical'}]
    reviews=[];current_gaps=[]
    if data['current']:
        from .current_views import build
        current_rows=[row for child in data['current'].values() for row in build(child)['rows']]
        reviews=[row for row in current_rows if row.assessment in {'Review','Critical'}]
        current_gaps=[row for row in current_rows if row.assessment=='Gap']
    gaps=[name+': '+('global 500-record cap reached; earlier records may be omitted' if row['record_limit_reached'] else row['state']+' ('+row['parse_state']+')') for name,row in data['query_coverage'].items()
          if row['state']!='available' or row['record_limit_reached']]
    if data['selection_state']=='unavailable':gaps.append('Requested previous boot/filter could not be resolved; no fallback was queried.')
    if data['scope_limit_reached']:gaps.append(str(data['omitted_boot_scopes'])+' additional boot scopes were omitted by the interpretation cap.')
    for child in data['investigations']:
        if child.get('unsupported_messages'):gaps.append('Some retained messages could not be interpreted.')
        for source in [child.get(key,{}) for key in ('ssh_analysis','firewall_analysis')]+child.get('event_search',{}).get('queries',[]):
            if source and (source.get('state') not in {'available','not_requested'} or source.get('unsupported_messages_in_response')):
                gaps.append('Some requested journal searches or message bodies could not be assessed.')
        if child.get('state')!='available':gaps.append('A boot partition has no usable main journal tail; independent source results remain available.')
    if faults:answer='Recorded problems to investigate: '+'; '.join(dict.fromkeys(finding['title'] for finding,child in faults)) +'.'
    elif data['state']=='unavailable':answer='The requested journal evidence could not be assessed. No fault or absence of faults can be established.'
    elif gaps:answer='Available records were checked, but the requested evidence has coverage gaps. What happened remains unverified.'
    else:answer='No supported fault pattern matched the readable records in this scope. This is not an all-clear.'
    if not faults and data['state']=='available' and not any(row['records_retained'] for row in data['query_coverage'].values()):
        answer='The journal queries completed but returned no records in this scope. No fault or absence of faults can be established.'
    from .investigation import unclassified_records
    if any(unclassified_records(child) for child in data['investigations']):answer+=' Unclassified warning/event records need manual review.'
    if data['mode']=='now':answer='Current measurements: '+str(len(reviews))+' review items; '+str(len(current_gaps))+' coverage gaps. '+answer
    if faults and (gaps or data['state']!='available'):answer+=' Some requested evidence could not be assessed.'
    crash_matches=sum(bool(row.get('panic_signature_lines')) for key in ('pstore','pstore_archive') for row in data.get(key,{}).get('records',[]))
    if crash_matches:answer+=' Independent crash fragments contain possible panic signatures; event time, boot association and cause are unverified.'
    for key,state in data.get('optional_sources',{}).items():
        if state not in {'available','not_requested'}:gaps.append(key+': '+state+'; optional evidence is incomplete.')
    start,end=(data['requested_window'][key] for key in ('since_realtime_us','until_realtime_us'))
    label={'now':'Problems now','period':'Selected period','before-restart':'Before restart'}[data['mode']]
    scope=label+'; '+('UTC '+utc(start)+' to '+utc(end) if start is not None else 'retained boot-filter evidence; restart boundary unverified')
    scope+='; boot filter '+str(data['boot_filter']['resolved'] or 'none')+'; journal '+data['journal_scope']['requested']+'.'
    return {'answer':answer,'scope':scope,'next':'Open a current reading or recorded report for its meaning, original evidence and next investigation. Review source gaps before attributing a cause.',
            'cause':'Underlying cause: Unknown. Current readings are not evidence of past conditions.',
            'ending':'Last retained records do not prove a crash, freeze or complete shutdown. Boot-local timelines remain separate.',
            'gaps':gaps,'shutdown':'Unknown'}


def render(data,out):
    from .presentation import line,render as render_source
    view=story(data)
    print('Faultlens - Investigate (read-only)',file=out)
    for key in ('answer','scope','cause'):line(out,view[key])
    for source in data['current'].values():render_source(source,out)
    for child in data['investigations']:
        line(out,'Retained boot identity: '+child['selected_boot']['boot_id'])
        render_source(child,out)
    for gap in view['gaps']:line(out,'Coverage gap: '+gap)
    for key in ('pstore','pstore_archive','atop'):
        if key in data:line(out,key+': '+data[key]['state']+'; independent source, boot association unverified. Use --json for retained fields.')
    line(out,'Next: '+view['next'])
    for limit in data['limitations']:line(out,'Limit: '+limit)
