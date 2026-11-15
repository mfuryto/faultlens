# Phase 3: optional local TCP/UDP socket snapshot

`network --sockets` and `security --sockets` add an independent current-namespace
snapshot to the existing counter sample. Default commands retain counter-only
collection. No Python dependency, daemon, database or external service is added.

The trusted command catalog invokes `ss -H -n -O -a -t -u`, with fixed arguments,
controlled environment, no shell/stdin, a two-second deadline and a combined stdout/
stderr 256 KiB cap. These options select numeric, headerless, single-line TCP/UDP
rows including listeners. No name resolution, remote probes or configuration
changes occur. See the [upstream ss manual](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/man/man8/ss.8).

Reported state counts and TCP listener-row counts summarize this snapshot without
inferring unique processes, clients or externally reachable services.

Six fields are validated: protocol, state, receive/send queues and local/peer
endpoints. IPv4/IPv6, wildcard ports/addresses and device-qualified addresses are
supported. Queues are unsigned 64-bit values and ports are 0–65535 or a wildcard.
At most 512 rows are accepted; output is never silently truncated to a successful
prefix. Unknown layouts, invalid fields, command failure, timeout or resource caps
make this source unavailable. Empty successful output is an available empty
snapshot, with completeness still unknown. Duplicate endpoints/rows remain
separate observations: shared bindings and transient changes are possible.

Both JSON and text retain numeric addresses, ports, queues and original accepted
rows without privacy masking. JSON escaping makes terminal control sequences
inert; malformed structural controls fail validation. No local report is saved or
uploaded automatically. The snapshot contains no owner/process collection, UNIX
sockets, bound-inactive TCP or observations from other namespaces. These omissions
are collection scope, not redaction. Owners and additional socket families are
possible later milestones with their own permission and resource tests.

Counter and socket availability are independent. Failure of one source yields a
partial report when the other is available; it never removes useful evidence.
The socket snapshot is sequential to counter sampling and must not be treated as
an atomic correlation. A LISTEN state confirms a reported listener only. UDP
UNCONN is not a TCP listener. Wildcard or non-loopback bindings do not establish
Internet exposure, policy bypass, malicious activity or root cause. Queue units
and interpretation depend on socket state; no generic queue-pressure threshold
is applied. Root/kernel compromise can falsify all local evidence.

Synthetic tests cover endpoints, bracket/scope variants, duplicates, empty output,
limits, malformed input, command failure, opt-in CLI scope, original evidence and
independent source availability. The fresh-process benchmark renders 512 invented
socket rows with 128 synthetic interfaces. Native validation reports only states
and counts; no real endpoint fixtures are committed.

## Readable interpretation

The default CLI explains each distinct protocol/state once, retaining every endpoint
row and annotating wildcard, loopback or specific local addresses. Empty and unavailable
snapshots are distinguished, with bounded/unsupported output never shown as a successful
prefix. The TUI exposes **Socket snapshot**, **Socket rows** and per-row explanations
on Network/Security pages when explicitly requested; e retains raw metadata access.
**Technical details** points to the original snapshot/row rather than a copy. Full report
and Evidence Explorer remain raw trees; JSON and collector behavior are unchanged.

TCP state descriptions follow the [RFC 9293 state overview](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.3.2).
UDP explanations follow [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html):
datagrams do not require a TCP-style connection, and a default peer association is
not a TCP handshake or delivery guarantee. Unsupported semantic combinations retain
their native state without borrowing TCP interpretations for UDP. Wildcard/loopback
annotations do not establish exposure or safety; forwarding, proxies, namespace,
device, family, routing and policy constraints remain outside this snapshot.

Queue numbers remain native ss values without universal byte units or pressure
thresholds. Ports do not identify applications. No reverse lookup, owner collection,
probe, new dependency, installation or configuration action is added. Tests cover
state meanings, scopes, empty/failure handling, duplicate rows, exact originals and
raw evidence roles. The 512-row benchmark includes readable CLI rendering and TUI
navigation to a socket explanation while retaining the original row by reference.
