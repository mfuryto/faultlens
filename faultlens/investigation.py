"""Read-only investigation narrative built from registered findings and exact source links."""
from datetime import datetime,timedelta,timezone

from .evidence_links import resolve

MAX_EXAMPLES=6


def utc(value):
    if type(value) is not int or not 0<=value<=253402300799999999: return 'Time not verified'
    return (datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=value)).isoformat(timespec='microseconds')


def excerpt(value,limit=512):
    if not isinstance(value,str): return 'No readable text; inspect retained original fields.'
    return value[:limit]+(' [excerpt; open original for full text]' if len(value)>limit else '')


def linked_records(data,finding):
    result=[]
    for reference in resolve(data,finding)['References']:
        for linked in reference['Retained source evidence']:
            record=linked['Original evidence']
            if not any(record is item for item in result): result.append(record)
    return result


def finding_detail(data,finding):
    from .presentation import finding_view
    detail=finding_view(finding)
    records=linked_records(data,finding)
    lines=[]
    for record in records[:3]:
        if 'message' in record:
            lines.append(utc(record['reference'].get('realtime_us'))+' | '+excerpt(record['message'],2048))
    if not lines:
        for reference in finding.get('evidence',[])[:3]:
            lines.append(utc(reference.get('realtime_us'))+' | '+finding['observation'])
    window=data.get('journal_window',data.get('event_search',{}).get('requested_window',{}))
    bounded=window.get('since_realtime_us') is not None or window.get('until_realtime_us') is not None
    return {'Source scope':('Requested journal receipt-time bounds apply to the tail and all journal searches; compare exact receipt times.' if bounded else
            'Broader event-search candidates cover the selected boot and can extend beyond the retained tail; compare exact receipt times.'),
            'Recorded evidence':lines or ['No separately retained original linked; inspect source references.'],
            **detail,'Evidence linkage':('Resolved '+str(len(records))+' retained source records.' if records else
            'Original message not retained or reference unresolved; no message was guessed.')}


def examples(data):
    from .presentation import finding_groups
    groups=finding_groups(data)
    rank={'critical':0,'warning':1,'informational':2}
    return sorted(groups,key=lambda item:rank.get(item[0]['severity'],3))[:MAX_EXAMPLES]


def story(data):
    groups=examples(data)
    faults=[row for row in groups if row[0]['severity'] in {'critical','warning'}]
    available=data.get('state')=='available'
    if faults:
        answer='Recorded problems to investigate: '+'; '.join(row[0]['title'] for row in faults[:2])+'.'
        step='Open a reported problem for its actual message, time and follow-up. Match it to your symptom before attributing the incident.'
    elif not available:
        answer='The selected journal evidence could not be assessed. No fault or absence of faults can be established.'
        step='Check the selected boot and journal scope. With existing authorized access, inspect journalctl --system --list-boots --no-pager; Faultlens never elevates.'
    else:
        answer='No supported fault pattern matched the checked evidence.'
        step='Set the incident boot/time in Settings, enable broader event search, and inspect the last retained message. No match does not rule out a failure.'
    if not faults and unclassified_records(data):
        answer+=' Unclassified warning/event records need manual review.'
    if available and not faults and data.get('event_search',{}).get('state')=='available':
        step='No supported fault was identified even with broader search. Match the incident time, inspect unclassified candidates and optional Atop/crash evidence; logging may not retain the cause.'
    selected=data.get('selected_boot')
    scope='Selected boot '+str(selected['index']) if selected else 'Boot not resolved'
    window=data.get('journal_window',{})
    scope+='; requested UTC '+(utc(window['since_realtime_us']) if window.get('since_realtime_us') is not None else 'open start')+' to '+(utc(window['until_realtime_us']) if window.get('until_realtime_us') is not None else 'open end') if window.get('since_realtime_us') is not None or window.get('until_realtime_us') is not None else ''
    scope+='; journal '+data.get('journal_scope',{}).get('requested','not verified')+'; '+str(data.get('records_examined',0))+' retained tail records.'
    gaps=[]
    if data.get('record_limit_reached'): gaps.append('Tail limit reached: earlier records were omitted; enable broader event search.')
    if data.get('journal_scope',{}).get('requested')=='visible': gaps.append('Visible scope may contain personal logs only. Select system journal for server evidence; existing access is required.')
    if data.get('event_search',{}).get('state') not in {'available','partial'}: gaps.append('Broader event search was not usable or not requested; the tail can miss earlier faults.')
    for query in data.get('event_search',{}).get('queries',[]):
        if query['state']!='available': gaps.append(query['query']+' search could not be assessed within its requested scope; no empty-success or wider retry is inferred.')
    for key,label in (('atop','Resource recording'),('pstore','Live crash evidence'),('pstore_archive','Archived crash evidence')):
        source=data.get(key,{})
        if source.get('state')!='available': gaps.append(label+': '+str(source.get('state','not requested'))+'.')
    crash=sum(bool(record.get('panic_signature_lines')) for key in ('pstore','pstore_archive') for record in data.get(key,{}).get('records',[]))
    if crash:
        answer+=' Crash fragments contain possible panic signatures; their boot/time attribution is unknown.'
        step+=' Open crash fragments and compare their content; do not attribute them to this boot automatically.'
    last=data.get('last_record')
    ending='Last retained journal receipt: '+utc(last.get('realtime_us'))+'.' if last else 'No last journal record was established.'
    ending+=' Later conditions are unknown; silence does not prove a freeze, crash or completed shutdown.'
    return {'answer':answer,'next':step,'scope':scope,'ending':ending,'gaps':gaps,
            'shutdown':data.get('shutdown_assessment','Unknown'),
            'cause':'Underlying cause: '+data.get('root_cause','Unknown')+'. A reported fault can explain a symptom without establishing its underlying cause.'}


def history_detail(summary):
    from .presentation import boot_summary_view
    detail=boot_summary_view(summary)
    first=summary.get('first_record');last=summary.get('last_record')
    detail['Retained UTC range']=utc(first.get('realtime_us'))+' to '+utc(last.get('realtime_us')) if first and last else 'Not verified'
    detail['Recorded examples']=[item['time']+' | '+item['title']+' | '+item['message_excerpt'] for item in summary.get('notable_reports',[])]
    return detail


def render(data,out):
    from .presentation import line,advice_line
    view=story(data)
    print('\nFault investigation',file=out)
    for key in ('answer','scope','cause','ending'): line(out,view[key])
    line(out,'Next: '+view['next'])
    records=data.get('journal_records',[])
    if records: line(out,'Last retained message: '+excerpt(records[-1]['message']),'  ')
    for finding,count,source in examples(data):
        detail=finding_detail(data,finding)
        line(out,finding['title']+' | '+str(count)+' source reports | '+source,'  ')
        for text in detail['Recorded evidence']: line(out,'Recorded: '+text,'    ')
        line(out,'Meaning: '+detail['What it means'],'    ')
        for step in detail['What you can do']: advice_line(out,step,'    ','Next: ')
    for record in unclassified_records(data):
        line(out,'Unclassified candidate: '+utc(record['reference'].get('realtime_us'))+' | '+excerpt(record['message']),'  ')
        line(out,'Source-selected warning/event only; meaning and cause were not classified. Inspect this original and neighboring records.','    ')
    if view['gaps']:
        line(out,'What may prevent an answer:')
        for gap in view['gaps']: line(out,gap,'  ')


def unclassified_records(data):
    """Resolve candidate examples only inside their own query and matching full reference."""
    rows=[]
    for query in data.get('event_search',{}).get('queries',[]):
        records=query.get('records',[])
        review=query.get('candidate_review') or {}
        for example in reversed(review.get('unclassified_examples',[])):
            index=example['candidate_index']
            if type(index) is not int or not 0<=index<len(records): continue
            record=records[index];reference=example['reference']
            if not all(record['reference'].get(key)==value for key,value in reference.items()): continue
            rows.append(record)
            if len(rows)==3: return rows
    return rows
