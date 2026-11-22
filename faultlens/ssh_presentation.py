"""Human-readable SSH statistics with direct original-record navigation."""
from .investigation import utc


def view(data):
    if data['state']=='unavailable':answer='SSH authentication could not be assessed. No zero-failure or safety conclusion can be drawn.'
    else:answer=('At least ' if data['scan_state']!='exhausted' else '')+str(data['totals']['failed'])+' explicit failed-authentication reports in the examined evidence.'
    window=data['requested_window']
    scope=('Since current/selected boot '+str(data['boot_filter'])+' through UTC '+utc(window['until_realtime_us']) if data['window']=='boot' else
        data['window']+' | UTC '+utc(window['since_realtime_us'])+' to '+utc(window['until_realtime_us']))
    if data['window']!='boot' and data['boot_filter']:scope+=' | optional boot '+data['boot_filter']
    coverage={
        'accessible_query_exhausted':'Reached the end of currently accessible matching records.',
        'current_boot_unavailable':'The current kernel boot identity could not be read; no wider query was substituted.',
        'command_unsuccessful':'The journal command did not provide a successful page; access and tool availability need local review.',
        'invalid_page':'A page had unexpected data or repeated/missing cursors; it was not counted.',
        'page_limit':'The page limit was reached. Select a shorter period for more focused coverage.',
        'evidence_limit':'The retained-evidence limit was reached. Select a shorter period.',
        'group_limit':'The username, peer or time-group limit was reached. Select a shorter period.',
        'time_limit':'The collection time limit was reached. Select a shorter period.',
    }.get(data['reason'],'Collection has not established coverage.')
    return {'Answer':answer,'Scope':scope+' | journal '+data['journal_scope']['requested'],
        'Coverage':str(data['records_examined'])+' original records; '+str(data['pages_read'])+' pages. '+coverage+' Complete logging remains unverified.',
        'Time buckets':str(data.get('bucket_seconds','Unassessed'))+' seconds per receipt-time bucket; only observed buckets are shown. Missing buckets do not prove continuous logging or inactivity.',
        'Other reports':'Totals could not be assessed.' if data['state']=='unavailable' else str(data['totals'].get('accepted',0))+' accepted; '+str(data['totals'].get('partial',0))+' partial; '+str(data['totals'].get('invalid_user',0))+' invalid-user context; '+str(data['unclassified_records'])+' unclassified.',
        'What it means':'Failed reports are counted separately from invalid-user and PAM context. Repeated records are not automatically distinct connections or attackers. Readable zero-match evidence differs from unavailable logs.',
        'What you can do':['Open usernames, reported peers and time buckets, then exact original records. Compare expected administrative activity; an accepted authentication alone does not establish compromise.',
            'If coverage is limited, select a shorter period. Missing history cannot be reconstructed by inventing totals.'],
        'Evidence limits':data['limitations']}


def render(data,out,*,details=False,evidence=False):
    import json
    from .presentation import line
    print('Faultlens - SSH authentication statistics (read-only)',file=out)
    for key,value in view(data).items():
        if key=='Evidence limits' and not details:continue
        for text in value if isinstance(value,list) else [value]:line(out,key+': '+text)
    for name,label in (('users','Reported usernames'),('peers','Reported peer addresses'),('timeline','Time buckets')):
        print('\n'+label,file=out)
        for row in data[name]:
            value=utc(int(row['value'])*1000000) if name=='timeline' else row['value'];counts=row['counts']
            line(out,value+' | failed '+str(counts.get('failed',0))+' | accepted '+str(counts.get('accepted',0))+
                ' | partial '+str(counts.get('partial',0))+' | invalid-user context '+str(counts.get('invalid_user',0))+
                ' | first '+utc(row['first_realtime_us'])+' | last '+utc(row['last_realtime_us']))
            if details:line(out,'Methods (all classified outcomes): '+json.dumps(row['methods'],ensure_ascii=True))
    if evidence:
        for row in data['records']:line(out,'Original: '+json.dumps(row,ensure_ascii=True))


def table(kind,data):
    from .workspace import Entry
    if kind=='ssh_report':
        detail=view(data)
        return 'SSH authentication statistics',('Report / source','Retained groups','Scope','Next step'),[
            Entry((label,str(len(data[name])),detail['Scope'],'Enter opens groups and original messages'),data,detail,'ssh_'+name)
            for name,label in (('users','Reported usernames'),('peers','Reported peers'),('timeline','Time buckets'))]+[
            Entry(('All original records',str(len(data['records'])),detail['Coverage'],'Enter opens messages'),data['records'],detail,'retained_records')]
    name=kind.removeprefix('ssh_');rows=[]
    for group in data[name]:
        label=utc(int(group['value'])*1000000) if name=='timeline' else group['value'];counts=group['counts']
        rows.append(Entry((label,str(counts.get('failed',0)),str(counts.get('accepted',0))+' / '+str(counts.get('partial',0)),
            utc(group['first_realtime_us'])+' to '+utc(group['last_realtime_us'])+' | invalid-user context '+str(counts.get('invalid_user',0))),[data['records'][index] for index in group['record_indices']],
            {'What it means':'Counts for this retained group; invalid-user context is separate. Open original records for methods and evidence.',
             'Counts':counts,'Methods (all outcomes)':group['methods'],'Evidence limits':data['limitations']},'retained_records'))
    return 'SSH '+name+' — observed reports, not distinct people',('Reported value / UTC','Failed reports','Accepted / partial','First / last UTC'),rows
