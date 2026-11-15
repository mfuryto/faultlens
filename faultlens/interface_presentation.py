"""Explain retained interface samples without resampling or stable-identity claims."""
from .presentation import size,duration

LIMITS=[
    'Current namespace and sequential snapshots only; interface names do not verify stable device identity.',
    'Rates use the measured batch interval and can hide short peaks. Virtual/physical layers can count the same traffic; do not sum them as host throughput.',
    'Error/drop growth is an observed counter change, not an attack, physical fault or verified root cause.',
    'Missing/decreased counters are not zero traffic. No baseline, packet payloads, routing or firewall policy is inferred.',
]


def measurements(row):
    values=row['per_second']
    if row['state']!='compared' or values is None:
        return ['Rates not comparable; no zero values are inferred.']
    result=['Receive '+size(values['received_bytes'])+'/s; send '+size(values['sent_bytes'])+'/s',
            'Receive '+str(values['received_packets'])+' packets/s; send '+str(values['sent_packets'])+' packets/s']
    for key,label in (('receive_errors','Receive errors'),('receive_drops','Receive drops'),
                      ('send_errors','Send errors'),('send_drops','Send drops')):
        result.append(label+': '+str(row['delta'][key])+' additional counter events; '+str(values[key])+'/s')
    return result


def interface_view(row,timing):
    if row['state']=='compared' and row['per_second'] is not None:
        meaning='Both retained snapshots support a nondecreasing counter comparison. This is not a sustained workload baseline or a device-health verdict.'
    elif row['before'] is None:
        meaning='This interface name was visible only in the second snapshot. Appearance or changed visibility prevents comparison; earlier traffic is not assumed to be zero.'
    elif row['after'] is None:
        meaning='This interface name was visible only in the first snapshot. Disappearance or changed visibility prevents comparison; later traffic is not assumed to be zero.'
    else:
        meaning='The retained counters could not be compared. A decrease can reflect reset, replacement or source semantics; no particular cause is established.'
    elapsed=timing.get('elapsed_seconds')
    return {'Observed':row['interface']+' | '+row['state'],'Measurements':measurements(row),
            'What it means':meaning,'Measured batch interval':duration(elapsed) if elapsed is not None else 'Not verified',
            'What you can do':['Repeat explicitly during the symptom and compare expected workload before changing interface, kernel or firewall settings.'],
            'Evidence limits':list(LIMITS),'Sample timing':timing,'Technical details':row}
