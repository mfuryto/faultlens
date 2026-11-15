# Phase 2: opt-in extended historical resource context

`diagnose --atop-date YYYYMMDD --atop-extended --json` adds historical disk, network
and process measurements from the same fixed local Atop recording and bounded window.
Without the additional flag, the existing CPU/MEM/SWP profile is unchanged. The date
and diagnose command are mandatory; incidents never multiplies this collection.

## Collection and administrator visibility

The isolated helper selects exactly `CPU,MEM,SWP,DSK,NET,PRC,PRM` and adds Atop's fixed
`-Z` option for space-normalized process fields. No PRG command-line record, per-process
network module, packet capture, arbitrary label, command or path is requested. Native
output, including names and wait channels, is now inspectable locally. Process
PID/TGID, names, states and wait channels are preserved alongside measurements. Disk
and interface names are exposed; existing fingerprints remain for comparison, not
anonymity or identity verification. Every validated sample retains the recorded
hostname and native replay lines. No automatic persistence or upload is introduced.
See [administrator Atop views](phase-3-atop-admin.md) for exact semantics.

All original descriptor/path protections, no-new-privileges, 64 MiB native address
space, two-second CPU/wall limits, output cap of 256 KiB and no file/core output apply.
The parent stops only at a complete validated extended SEP boundary. Every group must
have complete basic records plus exactly one NET upper record. Process PRC/PRM rows
must pair by PID with matching name/state/TGID/process flag and machine units.
Duplicate identities, unsupported layouts, mixed headers, partial groups and cap
violations reject the resource response. No larger/basic retry hides the failure;
journal findings remain available independently.

The supported extended prefixes were checked against official Atop 2.12.1 definitions.
This is deliberately narrower compatibility than the basic prefix parser. Maximums
per sample: 32 disks, 32 interfaces, 256 distinct process/thread IDs and 640 extra
rows, within the existing 256-sample and total-byte caps. Busy/large hosts can exceed
those bounds. Unsupported historical reader versions remain unavailable; installing
optional tools never reconstructs evidence that was not recorded.

## Normalized measurements

| Source | Exposed measurements | Interpretation |
| --- | --- | --- |
| DSK | Per-device I/O milliseconds, read/write operations and bytes | Recorded interval counters; sectors convert using 512 bytes; no utilization/failure inference |
| NET upper | TCP/UDP/IP counts and TCP established snapshot | Protocol accounting, not connection identities or attack detection |
| NET interfaces | Per-interface byte/packet/error/drop counters | No sum across virtual/physical layers; the same traffic may appear on several interfaces |
| PRC + PRM | Reported process count, excluded threads, exited count, aggregate CPU seconds, major faults and memory/swap snapshots | Only paired reported process rows; shared pages can be counted repeatedly |

Thread rows are excluded from process totals to avoid adding a process aggregate to
its threads. Exited rows remain counted, but their resource values are excluded from aggregates:
accounting/lifetime semantics need not localize those values to the sampled interval. Empty process/device/interface sets are labeled as unreported rows,
not proof that no activity occurred. RESET groups are validated but extended interval
measurements are excluded from interval aggregates. Per-record identities and reported
resources remain inspectable, including RESET, thread and exited rows. A PID/name is
not proof of a persistent process instance or a responsible workload.

These measurements belong to the referenced sample interval. Existing correlations
can indicate Possible wall-clock overlap with a journal finding; they never prove
host/boot identity, an attack, a responsible process, storage failure or root cause.
The normal CPU/memory limitations, interval averaging, unknown retention/coverage and
wall-clock uncertainty still apply. Complete reconstruction of a freeze is not promised.

## Verification

Synthetic checks cover units, record pairing, threads/exited rows, empty sets, RESET,
malformed/duplicate/oversized groups, native-helper fixed profile/guards, privacy and
independent journal results. The maximum-cardinality benchmark uses 32 disks, 32
interfaces and 256 processes. Integrated acceptance combines this profile with the
other explicit historical sources. No load, log-loss or crash is induced. Native
extended replay on supported Debian/Ubuntu targets remains an acceptance task; the
local helper test substitutes exec and does not claim actual recording compatibility.

Primary references: [Atop parseable field documentation](https://github.com/Atoptool/atop/blob/v2.12.1/man/atop.1),
[Atop output definitions](https://github.com/Atoptool/atop/blob/v2.12.1/parseable.c).
