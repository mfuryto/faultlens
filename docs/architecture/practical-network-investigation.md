# Practical network investigation

This completes delivery-plan step 3 using one investigation model: observed symptom,
source/time scope, numeric endpoints or reported service, concrete evidence,
alternative explanations and a proportionate next investigation. DDoS is one
example of possible traffic pressure, not the architecture. This is local incident
investigation, not a whole-host security/CVE audit or an intrusion-detection verdict.

## Current evidence

Network and Signals load practical context in the workspace. The CLI opts in with
`faultlens network --network-context --sockets`; the same context is available to
`security` and `investigate --mode now`. The basic counter-only CLI remains available
without additional native tools. Historical modes reject current context rather
than presenting current readings as evidence of earlier conditions.

Three independent short intervals retain original interface counter snapshots,
byte/packet rates and protocol before/after/delta values with measured timing. There
are six sequential batches, with unmeasured gaps between pairs. They are not a
continuous trace or a baseline. Resets/decreases, missing fields, changed interface
sets and invalid intervals remain unassessed. Counter values are unsigned 64-bit;
TCP MaxConn's documented -1 sentinel is accepted separately. No rate is invented
across a wrap/reset. Interface reuse without decreasing counters remains undetectable.
Never add overlapping virtual/physical interface layers as host throughput.

Optional extended sources add basic TCP opens/failures/resets/segments/retransmits
and IPv6 UDP datagrams/errors/buffer counters. TCP/TcpExt counters have namespace
aggregate scope, not an independently verified IPv4/IPv6 breakdown. IPv4 UDP and
IPv6 UDP have separate source states. Missing IPv6 evidence does not mean disabled
IPv6 or no IPv6 activity. Positive error/pressure deltas describe kernel reports;
overlapping counters are not independent incidents or calibrated attack likelihoods.

Fixed numeric read-only `ip -j address show` and separate IPv4/IPv6
`ip -j route show table all` commands retain local addresses, flags, operational
state, route types/tables, next hops and original metadata. No route lookup or remote
probe runs. An enabled interface reporting DOWN or an address reporting DAD failure
has a concrete review card with benign alternatives. Discard/reject/control routes
are informational configuration observations, often intentional. Policy rules, VRFs,
other namespaces and actual forwarding/Internet reachability are unverified.

When endpoints are requested, a separate `ss -H -n -O -a -t -u -p` query reads
reported owners. Only exact unique protocol/state/endpoints/queue matches join the
independent socket snapshots. Ambiguous, changed or missing matches do not guess an
owner. A bounded existing procfs worker can add reported system-service cgroup
associations. All reported names, PIDs, descriptors, addresses and source fields
remain accessible. Permissions, caps, namespaces, socket/PID reuse and sequential
reads limit attribution; these are reported associations, not verified identities.
User services are not promoted to system services. No packet-to-process attribution
or earlier service membership is inferred.

`ip` and `ss` are feature-specific optional tools, commonly supplied by iproute2.
No new Python dependency, daemon, service or recorder is required. Missing tools or
unsupported output make only their sources unavailable. No tool is installed or
privilege granted by collection. Configuration and owner queries use the existing
trusted executable catalog, fixed arguments, controlled environment/cwd, two-second
capture bound and 256 KiB combined output cap. JSON duplicate/nonfinite/structural
checks, at most 256 address/route rows and 64 addresses/next hops/flags per row apply.
Owner output retains at most 512 socket rows and 16 owners per row; unsupported or
over-limit replies expose no successful prefix. The process worker keeps its existing
512-PID/resource bounds. Kernel-uninterruptible I/O remains an OS deadline limit.

## Shared investigation cards

At most 32 cards describe counter/error growth across actual intervals, interface
conditions, listener queue pressure, repeated TCP states and reported peers. All
retained sources remain accessible even if cards are capped. Exact references and
thresholds remain in original details. More detail is an investigation aid, not
permission to restart, tune, block, delete or repair anything.

A LISTEN queue at least 80% of its reported nonzero backlog is a review observation
from one snapshot. Ten SYN-RECV/SYN-SENT/CLOSE-WAIT rows sharing a local endpoint
invite investigation, not a sustained-exhaustion or attack claim. Listening and
connected queues have different native meanings. Peer-review cards are informational:
there is no expected-peer configuration, direction inference from port numbers,
reputation lookup or automatic suspicious-peer classification. Legitimate clients,
monitoring, backups, proxies/NAT/load balancers and local applications are alternatives.

Existing boot-local journal readers supply scan-like multi-port reports, repeated
password failures and UDP-labelled report bursts. New patterns include at least
20 failures across three reported peers within five minutes, and password acceptance
after five failures from one reported peer within five minutes. These are Possible
patterns. Accepted passwords do not establish a session, authorization, compromise
or service misuse. Corrected typing and legitimate administration remain alternatives.
Narrow OpenSSH and UFW message coverage is unchanged: key/PAM/MFA and arbitrary
firewall/application formats are not silently declared covered. Configurable firewall
labels do not establish final packet verdicts. Report counts are not unique packets,
attempts, actors or attacks.

Historical cards retain actual reported peers/ports, source candidate indices,
receipt-time windows and original-record navigation. A follow-up opens the selected
period with authentication/firewall queries enabled and the optional boot filter
cleared. Query scope still uses Settings. The follow-up is not peer-filtered; compare
original fields and relevant service logs manually. This does not grant permissions
or prove temporal proximity is causal. Current cards can open their retained socket
rows, owner/service reader or the current/recent inquiry. Step 4 will further unify
cross-view incident context rather than expanding this step into a second roadmap.

Existing Atop interval rates require five preceding contiguous comparable samples
before a baseline comparison. RESET, gaps and missing series break comparison.
Host/boot identity remains unverified. Current snapshots cannot reconstruct an earlier
attack, per-peer UDP flows or unrecorded packets. Upstream saturation may happen
before traffic reaches the host; review existing edge/provider evidence when needed.
No provider API, capture, active scan, reputation service or production attack test
is introduced. No-source/no-match/quiet states never become an all-clear.

## Verification

Invented inputs cover dual-stack normal activity, legitimate high traffic, peer
expectation review, listener/state pressure, scan-like reports, repeated authentication
failures, acceptance after failures, UDP bursts and historical rate changes. Negative
cases include NAT/proxy ambiguity, missing/reset/wrapped counters, unavailable IPv6,
wrong-family addresses/routes, duplicate JSON, malformed owners, ambiguous joins,
caps and insufficient/gapped recordings. Textual tests traverse cards, socket rows,
owners/services, addresses, intervals, original records and period follow-up, including
compact resize. No real attack traffic is generated. The existing maximum socket
resource case now includes three intervals, 128 address rows, 256 routes per family
and 512 socket-owner rows without relaxing CPU/wall/memory budgets. Native source
and installed Debian/Ubuntu gates require the new contracts and exercise legitimate
partial/unavailable states independently. Disposable package-qualification containers
install iproute2 only to exercise real ip/ss formats before application networking is
disconnected. This does not add package dependencies or install tools on a user server.

Primary semantics: [kernel network counters](https://docs.kernel.org/networking/snmp_counter.html),
[ss options and queue context](https://man7.org/linux/man-pages/man8/ss.8.html),
[ip address reporting](https://man7.org/linux/man-pages/man8/ip-address.8.html) and
[ip route entries](https://man7.org/linux/man-pages/man8/ip-route.8.html).
