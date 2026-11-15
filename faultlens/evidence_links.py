"""Resolve normalized finding references within one retained report, without collection."""
import re

JOURNAL_FIELDS=('source','boot_id','realtime_us','monotonic_us','cursor_sha256')
LIMITS=[
    'Links describe references within this snapshot, not evidence authenticity or independent corroboration.',
    'Missing or ambiguous references are not guessed. Unopened sources are not collected.',
    'Journal receipt time is not necessarily event time. Atop host/boot identity remains unverified.',
]


def _owner(data,finding):
    sources=[('main',data.get('findings',[]),data.get('journal_records',[]),'journal_records')]
    for key in ('ssh_analysis','firewall_analysis','security_analysis'):
        source=data.get(key,{})
        sources.append((key,source.get('findings',[]),source.get('records',[]),key+'.records'))
    for index,query in enumerate(data.get('event_search',{}).get('queries',[])):
        sources.append(('event_search.'+query['query'],query['findings'],query.get('records',[]),
                        'event_search.queries['+str(index)+'].records'))
    owners=[(name,records,path) for name,findings,records,path in sources
            if any(value is finding for value in findings)]
    return owners[0] if len(owners)==1 else None


def _index(value,records):
    return type(value) is int and 0<=value<len(records)


def _digest(value):
    return isinstance(value,str) and re.fullmatch(r'[a-f0-9]{64}',value)


def _journal(reference,records):
    if 'candidate_index' in reference:
        index=reference['candidate_index']
        candidates=[(index,records[index])] if _index(index,records) else []
    elif _digest(reference.get('cursor_sha256')):
        candidates=list(enumerate(records))
    else:
        return [],'No retained candidate index or usable cursor hash; timestamps alone are not used to choose a record.'
    matches=[(index,record) for index,record in candidates
             if all(field in reference and reference[field]==record['reference'].get(field)
                    for field in JOURNAL_FIELDS)]
    if len(matches)!=1:
        return [],'No unique matching record in the finding source; other source lists are not substituted.'
    return matches,'One retained source record matches the reference.'


def _derived(data,reference):
    name=reference.get('source_analysis')
    if name not in {'ssh_analysis','firewall_analysis'}:
        return [],'Unsupported source reference; inspect the original reference fields.'
    records=data.get(name,{}).get('records',[])
    indices=reference.get('candidate_indices',[])
    matches=[]
    missing=0
    for index in indices:
        if (_index(index,records) and records[index]['reference'].get('source')=='systemd-journal'
                and records[index]['reference'].get('boot_id')==reference.get('boot_id')):
            matches.append((name+'.records['+str(index)+']',records[index]))
        else:
            missing+=1
    return matches,(str(len(matches))+' retained candidate references resolved; '+str(missing)+' unresolved. '
                    'These are contributing reports, not confirmed attacks or independent incidents.')


def _atop(data,reference):
    source=data.get('atop',{})
    digest=reference.get('output_sha256')
    if not _digest(digest) or digest!=source.get('output_sha256'):
        return [],'Captured-output hash is missing or differs; recording samples are not substituted.'
    matches=[]
    indices=[reference.get('sample_index')]+reference.get('baseline_sample_indices',[])
    for index in indices:
        samples=[sample for sample in source.get('samples',[])
                 if type(index) is int and sample.get('sample_index')==index]
        if len(samples)==1:
            matches.append(('atop.samples (sample_index '+str(index)+')',samples[0]))
    return matches,(str(len(matches))+' of '+str(len(indices))+' sample references resolved within the same captured output. '
                    'The first requested sample is the observation; remaining samples form its baseline. Host/boot identity is unverified.')


def resolve(data,finding):
    """Return small navigation wrappers that reference, rather than copy, source evidence."""
    owner=_owner(data,finding)
    if owner is None:
        return {'Scope':'Finding is not uniquely registered in this snapshot','References':[],'Limits':list(LIMITS)}
    name,records,path=owner
    values=[]
    for reference in finding.get('evidence',[]):
        if name=='security_analysis' and 'source_analysis' in reference:
            matches,explanation=_derived(data,reference)
        elif name=='security_analysis' and reference.get('source')=='atop':
            matches,explanation=_atop(data,reference)
        elif reference.get('source')=='systemd-journal':
            linked,explanation=_journal(reference,records)
            matches=[(path+'['+str(index)+']',record) for index,record in linked]
        else:
            matches=[]
            explanation='Measurements are embedded in this reference; no separately retained original record is linked.'
        values.append({'Source reference':reference,'Resolution':explanation,
                       'Retained source evidence':[{'Location':location,'Original evidence':value}
                                                   for location,value in matches]})
    return {'Scope':name,'References':values,'Limits':list(LIMITS)}
