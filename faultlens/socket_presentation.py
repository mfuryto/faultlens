"""Explain retained numeric socket rows without probes, lookups or policy inference."""
import ipaddress

TCP_STATES={
    'LISTEN':('Listening for TCP connections','The socket is waiting for incoming TCP connection requests; this does not verify an application or external access.'),
    'ESTAB':('TCP connection established','TCP reports an established connection. Application identity, authentication and authorization are not established.'),
    'SYN-SENT':('TCP connection attempt in progress','A TCP connection attempt is waiting for a response; one snapshot does not identify a failure or its cause.'),
    'SYN-RECV':('TCP handshake in progress','A TCP connection request is being processed; one snapshot does not establish a SYN flood or a failed connection.'),
    'TIME-WAIT':('TCP state retained after closing','TCP retains state after closing; this does not by itself identify a running service or a resource problem.'),
    'CLOSE-WAIT':('TCP waiting for local close','TCP has received a close request and is waiting for the local side to close. A single row does not prove an application leak.'),
    'FIN-WAIT-1':('TCP closing','TCP is closing the connection; completion and the reason for closing are not established.'),
    'FIN-WAIT-2':('TCP closing','TCP is closing the connection; completion and the reason for closing are not established.'),
    'LAST-ACK':('TCP waiting for final acknowledgment','TCP is completing a close; the snapshot does not establish whether it will complete normally.'),
    'CLOSING':('TCP closing','TCP is closing the connection; completion and the reason for closing are not established.'),
}


def state_meaning(row):
    if row['protocol']=='udp':
        if row['state']=='UNCONN':
            return 'UDP without a fixed peer','No fixed UDP peer is reported. UDP can send or receive datagrams without a TCP-style connection.'
        if row['state']=='ESTAB':
            return 'UDP peer associated','A UDP peer association is reported; UDP has no TCP-style handshake or verified delivery.'
        return 'Reported UDP state '+row['state'],'This UDP state is retained as reported; TCP state explanations are not applied to it.'
    return TCP_STATES.get(row['state'],('Reported TCP state '+row['state'],
        'The native TCP state is retained; no application or incident conclusion is inferred from it.'))


def binding_meaning(row):
    address=row['local']['address'].split('%',1)[0]
    if address=='*' or ipaddress.ip_address(address).is_unspecified:
        return 'Wildcard local address','A wildcard local address is reported. Address family, device, namespace and policy constraints still matter; Internet reachability is unverified.'
    if ipaddress.ip_address(address).is_loopback:
        return 'Loopback local address','A loopback local address is reported. This does not exclude forwarding, proxies or exposure through other services.'
    return 'Specific local address','A specific local address is reported. This row alone cannot establish interface state, selected routing or firewall policy; separately requested link/route configuration is not a connectivity test.'


def row_label(row):
    return (row['protocol'].upper()+' '+row['state']+' | local '+row['local']['original']
            +' | peer '+row['peer']['original'])


def row_view(row):
    state,meaning=state_meaning(row)
    binding,binding_limit=binding_meaning(row)
    return {'Observed':row_label(row),'State explained':state,'What it means':[meaning,binding_limit],
            'Local binding':binding,'What you can do':[
                'Compare this endpoint with expected application configuration and existing authorized logs before considering changes.',
                'Do not identify an application from its port number alone or change firewall rules from this snapshot.'],
            'Evidence limits':['Current namespace and current snapshot only; row counts are not distinct services or independent connections.',
                'Owner/service fields, when present, are reported sequential associations, not verified identities. Missing owner fields do not prove that no process owns the socket; policy and external reachability remain unverified.',
                'Queue numbers retain native ss semantics; listening and connected queues differ. No universal byte count, pressure threshold or traffic rate is inferred.'],
            'Reported owners':row.get('owners',[]),
            'Owner association':row.get('owner_state','Not requested'),
            'Technical details':row}


def snapshot_view(snapshot):
    if snapshot['state']=='available':
        count=len(snapshot['rows'])
        observed=str(count)+' socket row'+('s' if count!=1 else '')+' collected'
        meaning=[('No socket rows were returned; this does not prove that services are absent or that the host is secure.' if not count else
                  str(snapshot['tcp_listener_rows'])+' TCP listening rows reported. UDP rows are not counted as TCP listeners.'),
                 'This is a local namespace snapshot. Listening and wildcard bindings do not prove Internet reachability.']
    else:
        observed='Socket snapshot unavailable'
        state=snapshot['command_state']
        explanation={'missing':'No trusted ss executable was found; this optional feature is unavailable.',
            'timeout':'The socket command did not finish within the collection deadline; no partial row prefix is shown.',
            'output_limit':'The socket output exceeded a safe collection bound; no partial row prefix is shown.'}.get(state)
        if explanation is None:
            explanation=('Socket output was unsupported or exceeded a safe bound; no successful prefix is retained.'
                if snapshot.get('reason')=='unsupported_or_over_limit_output' else
                'The socket command did not provide a usable snapshot. This does not establish permission denial or absent services.')
        meaning=[explanation]
    return {'Observed':observed,'What it means':meaning,'What you can do':[
                'Review expected services and current source availability locally. No installation or configuration change follows from this snapshot alone.'],
            'Evidence limits':list(snapshot['limitations']),'Technical details':snapshot}
