# Phase 2: historical CPU accounting

Status: implemented additive normalized Atop sample fields, pre-release. No new
collector, command label, dependency, file, privilege or host setting is required.
The existing opt-in CPU/MEM/SWP replay supplies all necessary counters:

```sh
./bin/faultlens diagnose --previous-boot --atop-date 20260101 --json
```

Use the intended local recording date and journal scope. Each returned Atop sample
now separates execution, idle, I/O-wait and steal accounting. These fields describe
aggregate interval tick shares across the recorded CPUs, not per-CPU load, available
capacity or instantaneous peaks.

## Normalization

Atop's supported CPU prefix orders ticks as system, user, nice, idle, wait, hardware
IRQ, software IRQ, steal, then guest. The denominator is the sum of the first eight
tick counters. Guest is already included in user/nice accounting and is not added a
second time. Shares are rounded independently to two decimal places.

| JSON field | Tick numerator |
| --- | --- |
| cpu_execution_percent | system + user + nice + hardware IRQ + software IRQ |
| cpu_idle_percent | idle |
| cpu_iowait_percent | wait |
| cpu_steal_percent | steal |
| cpu_busy_percent | execution + steal; preserves the existing field's meaning |

The four separate state shares sum to approximately 100%; independent rounding can
leave a small difference. Legacy busy is not an additional disjoint state. A valid
zero counter yields zero. A RESET since-boot aggregate or zero total yields null
for every CPU percentage. Negative/malformed counters invalidate the replay under
the existing fail-closed policy; values are not clamped into a reassuring zero.

## Interpretation and trust limits

Kernel I/O-wait accounting has known limitations, including possible decreases.
This share is not disk utilization or latency and does not establish storage failure.
Steal describes reported involuntary wait; it does not identify a provider, competing
workload, overcommit policy or the cause of a freeze. Execution accounting is not
an independently measured capacity guarantee. Short spikes can disappear in an
interval average, especially with long recording intervals.

These values create no automatic findings or thresholds. Journal findings retain
their own confidence, resource pairing remains Possible temporal overlap, and host
and boot identity remain unverified. Root cause and shutdown outcome stay Unknown.
Existing replay bounds, evidence privacy, memory/swap semantics and clock-mapping
checks remain in force. Text output directs users to JSON for normalized samples
and includes the interpretation limitations.

## Verification

Synthetic tests independently exercise mixed and pure tick states, guest exclusion,
large counters, independent rounding, RESET/zero totals, negative wait rejection,
JSON privacy and unchanged finding/pairing confidence. The existing maximum-sample
benchmark asserts all four fields for 256 synthetic samples. No CPU contention,
real I/O pressure, recording modification or load generator is used. Target-host
accuracy and provider behavior are not established by synthetic tests.

References: [Atop 2.12.1 parseable CPU layout](https://github.com/Atoptool/atop/blob/v2.12.1/parseable.c),
[Linux CPU accounting limitations](https://www.kernel.org/doc/html/latest/filesystems/proc.html#miscellaneous-kernel-statistics-in-proc-stat).
