"""Three bounded independent intervals; no continuous recording or invented baseline."""
from datetime import datetime,timezone
from .network import collect


def sampled(sources=None,*,command='network',sample_seconds=.1,reader=None):
    reader=reader or collect;samples=[]
    for index in range(3):
        started=datetime.now(timezone.utc).isoformat()
        item=reader(sources,command=command,sample_seconds=sample_seconds,extended=True)
        samples.append({'sample_index':index,'started_at':started,'finished_at':item['collected_at'],
            'sample':item['sample'],'state':item['state'],'observations':item['observations'],'findings':item['findings']})
    data=item;data['network_samples']=samples
    grouped={}
    for sample in samples:
        for finding in sample['findings']:
            if finding['rule_id'] not in grouped:grouped[finding['rule_id']]=dict(finding,evidence=[])
            grouped[finding['rule_id']]['evidence'] += [dict(ref,sample_index=sample['sample_index']) for ref in finding['evidence']]
    data['findings']=list(grouped.values())
    data['state']='available' if all(row['state']=='available' for row in samples) else 'partial' if any(row['state']!='unavailable' for row in samples) else 'unavailable'
    data['counter_state']=data['state']
    data['limitations'].append('Three independent short intervals, not a continuous trace or workload baseline. Between-pair gaps, sequential reads, resets and interface reuse can hide or distort activity.')
    return data


def practical(sources=None,runner=None,*,command='network',sample_seconds=.1,sockets=False):
    data=sampled(sources,command=command,sample_seconds=sample_seconds)
    if sockets:
        from .sockets import attach
        attach(data,runner)
    from .network_context import collect as context
    data['network_context']=context(runner,sockets=data.get('sockets'),sample_seconds=sample_seconds)
    from .network_review import live
    live(data)
    if data['network_context']['state']!='available' and data['state']=='available':data['state']='partial'
    if data['state']=='unavailable' and data['network_context']['state']!='unavailable':data['state']='partial'
    data['collected_at']=datetime.now(timezone.utc).isoformat()
    return data
