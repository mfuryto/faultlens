# Phase 3, milestone 1: namespace network and security counter context

Status: initial read-only milestone, pre-release. This is not a complete network
security audit, historical attack detector or firewall/SSH assessment.

```sh
./bin/faultlens network
./bin/faultlens network --sample-seconds 0.2 --json
./bin/faultlens security --json
```

Both commands currently collect the same local counter context; security highlights
the supported observations without performing a remote scan or adding sources.
`network` also includes those findings so automation does not miss the interpretation.
The existing status command gains additive packet counts and rejects duplicate labels.

## Collection and bounds

Two sequential snapshots read only fixed `/proc/net/dev` and `/proc/net/netstat` paths
in the current network namespace. Sampling is one-shot, with a requested sleep of
0.05 through 1 second (default 0.1). The actual batch duration is measured with the
monotonic clock; rates never divide by the requested sleep. Intervals below 1 ms,
above 5 seconds, non-finite or nonpositive are unavailable. File reads retain the
existing 256 KiB, regular-file, no-final-symlink and strict UTF-8 policy. Kernel
filesystem calls have no hard deadline; no polling thread or external tool is added.

Each network snapshot accepts at most 128 unique validated interface names and the
supported exact header/16-counter layout. Rates are computed only for names present
in both snapshots with no decreasing observed counters. Added/removed/reset rows
remain visible without fabricated rates; the union can contain 256 labels. Namespace
and interface identity cannot be proven solely by names. Virtual interfaces can
count the same traffic as other layers, so their rates are not summed as host traffic.

Netstat parsing accepts at most 32 paired lines and 512 unique numeric columns per
section. Header/value prefixes and lengths must match; duplicate sections/fields,
negative counters, malformed or oversized input fail closed. Unknown columns are
validated but not echoed. Missing supported fields remain individually unavailable;
independent interface evidence survives a failed TCP source, and vice versa.

No IP addresses, ports, socket endpoints, process identities, packet payloads, DNS,
SSH logs, credentials or firewall rules are read. Interface labels/counter metadata
can still be sensitive: keep output local and review before manual sharing. No
runtime network sockets, command execution, dependency, elevation or configuration
writer is required.

## Evidence and interpretation

The supported TCP extension fields are SyncookiesSent, SyncookiesRecv,
SyncookiesFailed, ListenOverflows and ListenDrops. SYN-cookie counts describe the
kernel's cookie accounting. Listen counters describe recorded listener-side events;
they are not unique clients, independent incidents or attack counts.

A positive interval increase in SyncookiesSent, ListenOverflows or ListenDrops
creates a warning with source, before/after values, delta, measured duration, fixed
reasoning, threshold (at least one increment), limitations and local investigation
guidance. Confirmed means counter growth. Attack/root-cause assessment stays Unknown.
SYN-cookie configuration, legitimate bursts, listener processing and resource limits
can affect these counters; policy and traffic baseline are not inspected here.
Historical nonzero totals without current growth do not create warnings.

Zero deltas, absent indicators and empty interface sets do not establish security or
absence of host traffic. Source state available/partial/unavailable describes evidence,
not host safety. Ordinary observation state is unknown, not a healthy classification.
Exit zero means a report was rendered; consumers must inspect state and completeness.
Counters and timings are non-atomic observations, not packet traces or reliable
measurements of brief peaks. Root/kernel compromise can falsify local accounting.

## Verification and next scope

Synthetic tests cover elapsed-time normalization, resets, missing/changing interfaces,
large old totals, indicator growth without attack attribution, source independence,
unsupported/duplicate/malformed fields, caps, privacy and no sockets/subprocesses.
Fresh-process benchmarks exercise 128 interfaces and all three supported findings.
Native read-only smoke tests print only states/counts; a changed interface set yielded
partial evidence and another run completed. No live traffic is generated as a test.

SSH authentication, firewall events, connection states, UDP-specific analysis,
network link state, historical security evidence, sustained baselines and stronger
namespace/interface provenance remain future phase 3 work. Packet capture, active
probing and automatic firewall/sysctl changes are not introduced by this milestone.

Primary references: [Linux network statistics](https://docs.kernel.org/networking/statistics.html),
[kernel TCP counter definitions and limitations](https://docs.kernel.org/6.5/networking/snmp_counter.html).
