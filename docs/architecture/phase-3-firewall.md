# Phase 3: bounded firewall-labelled journal observations

Status: initial log-only firewall milestone, pre-release. It does not query or modify
active policy, install UFW/nftables, prove a packet verdict or identify an attack.

```sh
./bin/faultlens diagnose --boot 0 --system-journal --search-firewall --json
./bin/faultlens diagnose --previous-boot --search-firewall
```

## Collection and scope

The existing scope-specific listing resolves a boot to an immutable identity. One
additional fixed journal query selects `_TRANSPORT=kernel`, without a priority cutoff
or user regex. The query honors --since-us/--until-us inclusively and revalidates every
returned candidate, including the sentinel. A failed/unresolved boot never substitutes
another boot or broader source. No rule command, network connection, packet capture,
configuration writer, privilege escalation or new dependency is introduced.

This is a kernel-tail candidate query, not a complete prefix-indexed firewall search.
It requests at most 501 and retains 500 records, with the existing two-second deadline
and 256 KiB combined output cap. Unrelated kernel activity can consume these limits;
other transports, standalone ufw.log files, NFLOG/ulog and custom source paths are not
collected. Rate limiting, retention, permissions and absent logging hide traffic. Empty
or unmatched results do not establish firewall state, effective rules or security.

`firewall_analysis` reports its own availability, bounds, cap, unsupported/unclassified
counts, reported-label counts, original candidates, findings and filtered timeline.
It remains separate from SSH analysis, ordinary findings/reconstruction, shutdown
assessment and Atop pairing. Candidate intervals are not continuous logging coverage.

## Supported formats and claims

The parser recognizes the fixed labels BLOCK, ALLOW, AUDIT, AUDIT INVALID and LIMIT
BLOCK within a UFW-style kernel prefix. IPv4/IPv6 peers must be numeric and use the
same family. TCP/UDP records require source/destination ports 0–65535; ICMP/ICMPv6
require matching address family and type/code 0–255. Input/output interfaces can be
empty. Up to 64 bounded field/flag tokens are accepted. Duplicate identity/protocol/
port/type/code fields make classification ambiguous; the original remains inspectable.

Kernel logging can legitimately repeat LEN for IP and UDP layers. Ordered name/value
pairs preserve those fields instead of silently overwriting them. Flags are separate,
including an ACK flag alongside a numeric ACK field. Some option, fragment, nested
ICMP/error and unsupported protocol forms remain unclassified. No message is silently
declared benign merely because it does not match this initial parser.

A finding confirms a recorded supported log form and its reported label. Prefixes
are configurable, and LOG processing can continue to later rules. Therefore reported
BLOCK/ALLOW text is not a verified final packet verdict or proof that UFW is active.
`packet_verdict`, `attack_assessment` and root cause stay Unknown. Addresses are packet
fields, not authenticated clients or malicious identities. Retransmissions, repeated
records and multiple logging rules do not establish distinct packets, flows or attacks.
Privileged kernel-ring writers/imported logs and root/kernel compromise can falsify
local evidence; kernel transport is not cryptographic producer attestation.

## Administrator visibility and safety

Addresses, ports, interfaces, MAC/other recorded fields, flags, process metadata and
original messages/cursors are available locally without privacy masking. All retained
kernel candidates are inspectable, including unrelated, malformed-for-classification
or binary-content records. Invalid collection scope/JSON still rejects the source.
JSON escaping prevents hostile ANSI/OSC/bidi text from operating the terminal without
destroying decoded values. Reports are not saved or uploaded automatically.

Review originals and locally known policy before drawing a conclusion. The tool never
opens ports, blocks peers, changes rule counters or enables logging. Existing source
rights determine visibility; no installation or system change is needed to read
already-recorded evidence.

## Verification and next scope

Synthetic tests cover supported labels/protocols, repeated LEN, port zero, ambiguous
fields, source spoofing/sentinels, time/boot/scope constraints, independent failures,
empty/unrelated results, full local evidence and terminal safety. The maximum-candidate
benchmark combines 500 firewall reports with SSH and both existing filtered searches
plus original journal evidence. Timeline references avoid repeating packet context;
full context remains in finding evidence and originals.

Target-host log detection and broader backend compatibility still require validation.
Custom nftables/iptables prefixes, active ruleset inspection, sustained anomaly baselines
and attack attribution remain future work. This milestone does not complete phase 3.

Primary references: [UFW distribution backend](https://sources.debian.org/src/ufw/0.36.2-10/src/backend_iptables.py/),
[kernel log field rendering](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_log_syslog.c),
[non-terminating LOG target](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/xt_LOG.c).
