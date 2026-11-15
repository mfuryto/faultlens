# Phase 2, milestone 2: optional Atop recordings and temporal context

Status: implemented opt-in adapter, synthetic tests and a limited native replay
smoke test with Atop 2.12.1. Broader deployment validation remains required. This
is temporal context, not full incident reconstruction or proven attribution.

## Usage and prerequisites

Faultlens requires no new Python package. To enable the optional historical recorder
on a Debian/Ubuntu system, the administrator may explicitly install and start the
existing distribution service:

```sh
sudo apt update
sudo apt install atop
sudo systemctl enable --now atop.service
systemctl status atop.service --no-pager
atop -V
```

This changes the host by enabling the existing local recorder; Faultlens never runs
these commands or installs/configures a service automatically. Records accumulate
from installation onward and do not reconstruct past measurements. Recordings can
contain sensitive process information; do not publish them or make them world-readable.
No Faultlens daemon, database or collector is added. Keep the distribution tool maintained.

After the recording exists, use the date of the desired local recording:

```sh
./bin/faultlens diagnose --previous-boot --atop-date 20261114
./bin/faultlens diagnose --boot 0 --atop-date 20261114 --json
```

The date is an explicit input, not a live lookup or automatic traversal. It selects
only `/var/log/atop/atop_YYYYMMDD`. An incompatible version, missing tool/file or denied
access leaves resource history unavailable without hiding journal findings. There is
no arbitrary-path option, pip dependency, implicit sudo, group change or chmod.
Without the flag, journal analysis does not open a recording or execute Atop.

## Source and command boundaries

`recordings.py` validates a real calendar date from 1970 onward and walks `/var/log/atop`
using directory descriptors and O_NOFOLLOW. Directories and the final regular file
must be root-owned. Recording directories/files cannot be group/world writable;
`/var/log` alone may be group-writable for distribution syslog layouts, but never
world-writable. The next protected root-owned directory and final inode are checked
and pinned. Final files must be nonempty and <=256 MiB. O_NONBLOCK avoids FIFO hangs
before type validation; symbolic links and non-regular objects are rejected.

Only the opened read descriptor is passed to a fresh isolated Python helper. The
native command uses the descriptor path `/proc/self/fd/N`, not a re-opened filename:

```text
atop -r /proc/self/fd/N -P CPU,MEM,SWP -b YYYYMMDDhhmmss
```

Atop 2.12.1 can select an additional screen handler when its `-e` option is used,
even with parseable output. A native smoke test exposed this mixed output, which
the strict parser rejected. Faultlens therefore omits `-e` and enforces the end
boundary in the parent: stop only after a complete, strictly validated SEP-delimited
group reaches the requested end time. Report this as `window_complete`, without
inventing a native exit code. Incomplete/malformed groups never establish completion.
EOF with a genuine successful exit remains `completed`. The byte/CPU/wall caps apply
while seeking the window, and only in-window samples are included in the report.

The descriptor avoids filename replacement races and the native named-file `.gz` fallback.
The inode can still change if the recorder appends or an administrator modifies it;
this is not a content snapshot or authenticity guarantee. Root-controlled paths do
not prove that records belong to the current host or selected boot.

The helper selects only fixed standard Atop executable paths, rejecting arbitrary
programs or nonstandard resolved destinations. The helper runs with `-I -B` (isolated, no bytecode-cache writes), a fixed environment, nonexistent HOME, UTC timezone, no
user loader/Python environment, no stdin, no shell and no new privileges via Linux
PR_SET_NO_NEW_PRIVS. It sets limits in the child only, before native exec:

| Native replay guard | Limit |
| --- | ---: |
| Address space | 64 MiB |
| CPU | 2 seconds |
| Regular-file growth | 0 bytes |
| Core dump | 0 bytes |
| Parent-enforced collection deadline | 2 seconds, plus up to 1 second for reap cleanup |
| Combined stdout/stderr | 256 KiB |

The native tool and its global configuration remain trusted system dependencies;
these guards are not a complete syscall/network sandbox. No privilege is granted;
a user who already runs as root remains root. The helper refuses execution if its
no-new-privileges guard fails. Pipes and the original recording descriptor are closed even if child cleanup fails.
Resource exhaustion or unsupported raw data yields
unavailable context. Do not widen limits or permissions automatically to mask failures.
By default only CPU/MEM/SWP system records are requested; process, command-line, disk-device,
network-address and cgroup records are not requested. Both profiles now retain the
recorded hostname and validated native replay lines for local administrator inspection
through --json or --show-evidence. Native stderr is not rendered by this adapter.
Native source code is not vendored. See [administrator Atop views](phase-3-atop-admin.md).

## Format and measurement semantics

The CPU/MEM/SWP field prefixes were checked against official Atop v2.8.1, v2.10.0
and v2.12.1 sources. Newer append-only numeric fields can be ignored; reordered,
malformed or unsupported prefixes fail closed. Raw binary versions are delegated
to the installed Atop reader, including its installed-version fallback behavior.
Raw-file compatibility across releases is not assumed.

Require complete CPU/MEM/SWP groups with SEP, consistent hostname/time/interval,
UTC header agreement, no duplicate labels and increasing sample times. RESET is a
since-boot aggregate; its CPU result is null and it is excluded from temporal pairing.
Also report null for non-advancing CPU totals, never a healthy zero. CPU busy excludes
idle/iowait and avoids double-counting guest ticks already included in user time.
Legacy busy includes steal. Separate execution, idle, I/O-wait and steal percentages
are now available; see [historical CPU accounting](phase-2-atop-cpu.md) for exact
denominators, RESET handling and interpretation limits.
Memory total/free/cache and swap total/used are byte snapshots. Free pages are not
MemAvailable; these fields do not establish memory pressure or an OOM cause.

At most 256 groups and 500 temporal pairs are handled, independently of the byte
cap. Incomplete, mixed-source, backwards-clock or oversized output is unavailable;
there is no silent prefix analysis. The captured output's SHA-256 fingerprint aids
local comparison and is not evidence authentication. Sampling interval is preserved
in each sample, and the plain CLI lists observed non-RESET intervals. A 600-second
interval is supported and tested, but cannot reveal short peaks or intermediate
memory states. The proposed 30-second interval requires target-host overhead and
retention testing before any configuration change.

## Temporal pairing and uncertainty

The 30-minute resource window is centered on the last accessible journal record,
including up to 15 minutes after it to allow interval samples to finish. One selected
file can omit midnight/rotation neighbors, and long sampling gaps can leave no match.
If the journal's realtime-minus-monotonic mapping varies by more than two seconds,
resource pairing is withheld as ambiguous. Clock changes, suspend and drift can all
invalidate a simple wall-time mapping; no specific cause is inferred.

A journal event can be paired only when its realtime lies in a non-RESET CPU interval
`(sample_end - interval, sample_end]`. Pairing confidence is always **Possible**,
with host identity and boot identity explicitly **unverified**. Memory/swap values
are snapshots at the interval end, not the event time. Two sources sharing a clock
range does not prove they came from the same boot/host or establish causality.
Confirmed journal events keep their existing confidence; their cause and the overall
root cause remain Unknown. The pairing cap is reported explicitly when reached.

Plain output summarizes availability, observed intervals and possible-pair count.
`--json` exposes normalized resource values and references only after the explicit
opt-in. There is no report persistence or automatic upload. Review even summarized
output before manually sharing it.

## Verification and remaining work

Tests use invented Atop groups and fake replay results. They cover units, guest
accounting, RESET, no swap, format/time/source inconsistencies, truncation/caps,
missing tools, symlink-safe descriptor walking, native invocation, date/path rejection,
coarse sampling, false causal claims and child-only resource/no-privilege limits.
A separate isolated test exercises actual Linux limits and no-new-privileges without
executing Atop or reading a real recording. CI never reads its host's recordings.
A local 2026-11-14 smoke replay with Atop 2.12.1 validated both EOF and parent-enforced
window completion, and normalized RESET and non-RESET groups. Only structural counts
and execution states were emitted; no source values, identifiers or real fixtures
were copied into the repository. This is not validation of every raw format, target
host, historical incident or native performance profile.

Synthetic fresh-process benchmarks include the largest supported combination of
journal findings and resource groups. They measure Faultlens, not actual native
Atop replay, disk I/O or the recording daemon. Next steps include native compatibility
validation, richer provenance, historical disk/process/network data, preservation and
retention assessment, and carefully tested configuration recommendations.

Primary references: [Atop manual](https://www.atoptool.nl/download/man_atop-1.pdf),
[official parseable interface](https://github.com/Atoptool/atop/blob/v2.12.1/parseable.c),
[raw replay implementation](https://github.com/Atoptool/atop/blob/v2.10.0/rawlog.c),
[2.12.1 option/handler selection](https://github.com/Atoptool/atop/blob/v2.12.1/atop.c),
[Debian package](https://packages.debian.org/stable/atop), and
[Ubuntu package](https://packages.ubuntu.com/noble/atop).

See [coverage hints](phase-2-coverage-pstore.md) for the subsequent bounded filename-date
and sample-interval gap assessments. They do not establish recording continuity.

The explicit [extended profile](phase-2-atop-extended.md) adds bounded disk/network
and process resource context; it is never enabled by the recording-date flag alone.
