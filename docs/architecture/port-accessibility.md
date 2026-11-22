# Local port evidence and external accessibility

Approved network step 3 adds Network → Port accessibility and `faultlens ports`.
The reader connects current TCP listeners/unconnected UDP bindings to reported
owners/current service associations, assigned addresses, route configuration,
conditional filtering and NAT declarations. Internet accessibility remains
unverified until a separate authorized observation from an independent network.
No active network operation or automatic external test is introduced.

## Sources and boundaries

Read `ss -H -n -O -4 -l -t -u -p` and its `-6` counterpart separately. Retain
the accepted complete output, queues, state, numeric endpoints and all reported
owners. A wildcard printed as `*` has the family of its explicit query. Validate
TCP LISTEN/UDP UNCONN and the selected family; reject the whole source for unknown
format, controls, missing/zero local port, over 512 rows or 256 KiB. Native reads
use the existing trusted executable catalog, controlled environment, fixed argv,
two-second capture, no shell, no DNS, no elevation and no configuration changes.
Do not infer per-socket IPV6_V6ONLY from a system default or IPv6 wildcard binding.

Independent existing `ip` JSON readers retain addresses and IPv4/IPv6 route tables
(256 rows, 64 address entries per interface, 256 KiB). Nftables and IPv4/IPv6
iptables-save retain their 192-KiB nft / 128-KiB iptables and 2,048-object/line limits. Backend version
reports distinguish legacy/compatibility evidence; native nft and nf_tables
compatibility views can overlap. No UFW or Fail2ban action, container daemon API,
namespace entry, sysctl write, trace or packet capture runs. No dependency changes.

The overall budget is 20 seconds checked before each read. A last native read can
add its two-second deadline, excluding parsing/scheduling. At most one existing
bounded process worker samples current procfs after owner reports to associate
reported PIDs with current cgroups/service names. PID/start-tick references and
sequential-observation limitations remain visible; this does not prove membership
at the earlier socket observation. Missing process data does not discard ss owners.
No new daemon, database, saved preferences, recording or evidence export is added.

Every source keeps its command state, exit status, start/end time, parse reason and
accepted originals. Missing/failed/unsupported and empty readable output differ.
An unavailable listener family does not become zero services. Sources are
non-atomic and current-namespace only; root/kernel compromise can falsify them.

## Association and interpretation

Show IPv4/IPv6, TCP/UDP, exact binding, reported owner/service and binding category.
Classify loopback, wildcard, link-local, multicast and private/shared/special-use
addresses; global scope is not a connectivity verdict. Associate explicit bindings
by numeric address and optional interface zone, or list same-family addresses for
a wildcard. Preserve link state/flags and tentative/DAD/deprecated metadata.
At most 32 candidate addresses are previewed, with an explicit cap. A loopback
socket does not exclude another listener, proxy, NAT or upstream publication.

Build references to compatible protocol/destination-port expressions and rules
with all-port or unresolved conditions. Decode literal equality/inequality,
numeric port lists/ranges/inline sets, nft TCP/UDP payload predicates/l4proto and
iptables protocol/dport forms. Unknown maps/named port sets and other predicates
remain unresolved. Family, source/destination/interface/connection-state conditions,
rule order, jumps/goto, priorities, later hooks and return paths still apply.
References are not a simulated packet verdict. Preview at most 32 references per
port, preferring literal port predicates and input ancestry; order is relevance,
not packet evaluation order. All original rules remain available.
Each candidate also retains up to eight direct incoming jump/goto rule references
and their original conditions, with a cap flag. A source-only child rule must not
be mistaken for unconditional applicability when its caller restricts the port.

Show input/forward/prerouting/ingress default policy context and candidate chain
ancestry. Follow declared chain links backward with a 64-chain walk bound; cycles
terminate and capped walks are identified. Unknown ancestry stays unknown rather
than proving irrelevance. Base policy applies only when evaluation reaches the end
of that chain. An accept expression can precede a later drop. Counts describe
expressions/declarations, not distinct services, verified exposure or corroboration.

Retain DNAT and redirect declarations even when no host listener exists. Decode
simple literal nft targets and IPv4/bracketed-IPv6 iptables targets/ports; dynamic
targets, ranges and implicit redirect addresses remain unresolved with originals.
For a literal target/port, link candidate post-translation policy and compatible
same-namespace target sockets within the retained preview. Wildcard socket joins
also require a corresponding assigned address. Missing association does not prove
an absent container or service. Neither a container runtime nor target namespace,
forwarding enablement, live target, upstream mapping or return path is inferred.

Preview at most 128 listener/bound-UDP rows and 128 translations; report caps and
retain full accepted source evidence. No unsupported rule is silently evaluated as
allow/deny. Reading rules under existing access does not certify a complete policy.

## External verification and navigation

Open a port, then Policy, Addresses, Routes or Reported service. Policy shows actual
source/chain/handle, conditions, actions, counters, ancestry and base defaults.
Forwarding opens the declaration, candidate target-policy references and any
observed target sockets. Original fields and Evidence pins retain exact source
context. The modal uses the existing serial cancellable collection lifecycle;
cache reuse is explicit, refresh drops old data and failure does not revive it.
There is no history/boot selector for a current binding inquiry.

External check gives manual protocol-specific guidance without running a command.
Independently establish the intended public endpoint (which may differ under
upstream NAT), test only an authorized target from an independent external network,
and record source/network, numeric target/port, IPv4/IPv6, TCP/UDP, UTC time and
actual response/result. A server-local, same-LAN or proxied test can be another path.
TCP connect success verifies only that observed transport path at that time;
application health needs a separate check. UDP requires a valid safe service-specific
request and matching response: send success or silence does not prove open/closed.
Timeout/refusal has several possible causes. No user-entered assertion is promoted
to verified evidence; this version does not import external test results.

## Acceptance

Synthetic tests cover dual stack, wildcards/loopback/link-local scopes, owner/service
associations, source failures/empty/malformed/capped data, literal/negated/ranged
port predicates, cyclic ancestry, dynamic and literal NAT, missing host listeners,
target policy/socket links and TCP/UDP verification limits. Real frontend tests
follow policy/original/address/route/service/external-help and pinned evidence,
compact resize, cache reuse, refresh cancellation and failed replacement. Existing
SSH and firewall regressions remain required. Two resource scenarios retain 128
listener previews and 257 nft rules under unchanged CPU/wall/RSS limits. Native and
installed Debian/Ubuntu qualification adds the tenth CLI contract and a real port
modal collection. These passes are software acceptance, not an Internet scan.

Primary references: [ss options](https://man7.org/linux/man-pages/man8/ss.8.html),
[IPv6 socket semantics](https://man7.org/linux/man-pages/man7/ipv6.7.html),
[nftables hooks/verdicts](https://netfilter.org/projects/nftables/manpage.html),
[nft JSON/NAT schema](https://manpages.debian.org/bookworm/libnftables1/libnftables-json.5.en.html).

## New-flow INPUT assessment after 1.2.0

The port list now reports **Allowed**, **Blocked**, **Source dependent**,
**Interface dependent**, **Source/interface dependent**,
**Address/interface dependent**, **Unresolved**, **No INPUT chains** or
**Unavailable** for collected IP/inet INPUT policy. This is a new tracked TCP SYN
or UDP flow assessment, not a whole-kernel or Internet verdict. Bound address/zone
and existing source access still apply. For wildcard bindings, loopback/multicast
addresses are excluded from the non-loopback target assessment. The interface
owning an assigned address is never assumed to be the incoming interface: weak-host
routing, loopback VIPs and bridges can differ. Interface predicates range over the
collected non-loopback interfaces (loopback interfaces for loopback bindings),
with a bounded preview of candidates. Conditional interface paths stay visible.
Missing/capped
address context remains unresolved where conditions need it. Loopback-only binding
scope remains separately visible.

Evaluate supported literal protocol/port/address/interface predicates, source
prefixes/named address sets and NEW conntrack state with three-valued matches.
Respect rule order, jump/return/goto and base defaults; an accept in one base
chain does not override a drop in another. Unknown source predicates explore both
branches. All supported branches must allow for Allowed; a definite input drop
is Blocked. Mixed source branches are conservatively Source dependent, not an
exact ACL expansion or proof that a particular peer is admitted. Other unresolved
conditions/actions never become a guessed allow. Address/interface differences
retain per-target assessments; named/numeric protocol/family/state forms are
recognized. Existing/related flows are not certified by a new-flow assessment.

Unsupported maps, transformations, match extensions and non-INPUT routing/NAT/
forwarding paths stay explicit. Source and rule/default references remain local
and inspectable. The native nft view takes presentation precedence over reported
nf_tables compatibility views; a legacy view remains separately identified and
unreadable sources are coverage gaps. No INPUT chain in a readable view does not
prove absent filtering in other views/hooks. External verification remains a
separate manual inquiry and is not repeated as each port's policy result.

The interpreter allows at most 128 source/flow contexts, 32,768 rule visits per
report, 4,096 per context and depth 24; repeated identical contexts reuse results.
Cycles, malformed structures and budget exhaustion are Unresolved. Flow/evaluated
rule previews are bounded; original sources are unchanged. Assessments include
exact source/target/interface scope, readable reasons, base policies and original
fields. These are interpretations of collected snapshots, not authenticated
proof of live traffic or future policy.

References: [nft verdict semantics](https://netfilter.org/projects/nftables/manpage.html),
[Linux protocol families](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter.h)
and [conntrack states](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_conntrack_common.h).
