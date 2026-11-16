# Resource benchmarks and historical baselines

Run from a trusted source checkout on Linux with Python 3.11+ and the optional
frontend environment installed, so all CLI and actual Textual modes are measured:

```sh
.venv/bin/python scripts/benchmark.py --iterations 10
```

Each measurement starts a fresh isolated Python process, uses invented `/proc`
content, a synthetic root filesystem and fixed fake command results, and renders
the real CLI JSON into memory. No live diagnostic collection or report upload occurs.
Status retains its real default 0.1-second CPU sampling delay. Wall time includes
process startup; CPU and peak RSS are measured per child using `getrusage` (Linux
ru_maxrss KiB converted to MiB). Each command gets its own fresh children so a
previous command's RSS peak cannot contaminate later measurements.

Local baseline, 2026-11-11, Linux x86-64, Python 3.14.4, 10 fresh children per command:

| Command | Median startup + collection wall | Max wall | Median CPU | Max peak RSS |
| --- | ---: | ---: | ---: | ---: |
| status | 0.1451 s | 0.1483 s | 0.0335 s | 18.52 MiB |
| check | 0.0384 s | 0.0418 s | 0.0325 s | 18.41 MiB |

These results establish a synthetic development baseline, not a guarantee for Debian,
Ubuntu, containers or small VPS systems. External tool startup, journal size, disk
latency, access restrictions and large device/process sets are not modeled. Optional
commands have independent deadlines and bounded output in the runtime.

The unittest suite measures two children per command. Current regression budgets
are <50 MiB peak RSS for CLI modes and <80 MiB for the optional Textual workspace,
with <1 s CPU and <2 s wall per invocation. Earlier tables below describe historical
implementations, including the removed curses frontend.
The benchmark exits nonzero on a budget violation. Repeat on the target VPS and
record distribution, Python version, collection size and resource consumption before
claiming operational performance. Do not commit diagnostic data from those tests.

## Journal milestone measurements

The benchmark now includes history and diagnose. Diagnose processes a worst-case
invented 501-record journal response with 500 recognized events after applying the
cap, formats the full JSON report in memory, and retains the same <50 MiB / <1 s CPU
/ <2 s wall regression budgets. No live journal is collected. The resource regression
test runs two fresh children for each of the four commands.

Local measurements on 2026-11-11, Linux/Python 3.14.4, ten children per command:

| Command | Median startup + collection wall | Max wall | Median CPU | Max peak RSS |
| --- | ---: | ---: | ---: | ---: |
| status | 0.1453 s | 0.1479 s | 0.0343 s | 18.40 MiB |
| check | 0.0391 s | 0.0395 s | 0.0334 s | 18.31 MiB |
| history | 0.0416 s | 0.0433 s | 0.0354 s | 22.82 MiB |
| diagnose | 0.0534 s | 0.0545 s | 0.0468 s | 25.52 MiB |

These figures exclude real journalctl startup, access restrictions and real journal
I/O. The subprocess deadlines and byte cap remain independent runtime controls.

## Optional Atop context — 2026-11-14

The `diagnose-atop` benchmark is a synthetic diagnostic invocation with 501 invented
journal records (500 retained events), 256 resource groups and possible temporal
pairings. No native Atop binary or recording is used. All five benchmark modes retain
the <50 MiB parent RSS / <1 s CPU / <2 s wall regression budgets.

Linux/Python 3.14.4, ten fresh children per command:

| Command | Median wall | Max wall | Median CPU | Max peak RSS |
| --- | ---: | ---: | ---: | ---: |
| status | 0.1494 s | 0.1551 s | 0.0367 s | 18.14 MiB |
| check | 0.0371 s | 0.0388 s | 0.0316 s | 18.11 MiB |
| history | 0.0406 s | 0.0419 s | 0.0342 s | 22.72 MiB |
| diagnose | 0.0516 s | 0.0522 s | 0.0450 s | 25.39 MiB |
| diagnose-atop | 0.0712 s | 0.0748 s | 0.0641 s | 26.84 MiB |

Native replay and the recording daemon are not included. Native replay has separate
64 MiB address-space / 2 s CPU / 2 s wall limits; it is not measured by the
synthetic benchmark. A separate limited native smoke test verified EOF and cutoff
handling but did not establish a native resource/performance baseline. Neither
these synthetic results nor the limits establish target-host overhead or justify changing an existing sampling interval automatically.

## Preservation assessment — 2026-11-14

The sixth mode, `check-history`, exercises synthetic merged configuration, literal
Atop defaults and bounded metadata through the real CLI. Ten fresh children on
Linux/Python 3.14.4 measured median wall 0.0423 s, maximum wall 0.0464 s, median CPU
0.0360 s and maximum peak RSS 22.74 MiB. All six modes passed the existing budgets.
This excludes native systemd-analyze startup and live filesystem latency. The resource
regression test now runs two fresh children for each of the six modes.

## Coverage hints and live pstore — 2026-11-14

The seventh mode, `diagnose-pstore`, analyzes eight invented pstore text records
(512 KiB total) plus the bounded synthetic journal; it never reads host pstore.
Ten fresh Linux/Python 3.14.4 children measured median wall 0.0583 s, maximum wall
0.0613 s, median CPU 0.0507 s and maximum peak RSS 25.47 MiB. Diagnose-atop, now
including interval coverage, measured median wall 0.0776 s and maximum peak RSS
27.05 MiB. All seven modes retained <50 MiB RSS / <1 s CPU / <2 s wall budgets.
The regression suite now runs two fresh children for each of seven modes.
These are synthetic parser/CLI measurements, not kernel filesystem latency guarantees.

## Systemd pstore archive — 2026-11-14

The eighth mode, `diagnose-pstore-archive`, injects eight invented raw records
(512 KiB total) into the real archive parser/CLI alongside the bounded journal.
Ten fresh Linux/Python 3.14.4 children measured median wall 0.0638 s, maximum wall
0.0653 s, median CPU 0.0556 s and maximum peak RSS 25.54 MiB. All eight modes passed
the existing <50 MiB RSS / <1 s CPU / <2 s wall budgets. The resource regression
suite now checks two fresh children per mode. Live/archive benchmark modes also
assert that all eight records were analyzed successfully, not merely journal success.
Real archive directory traversal and filesystem latency are excluded; separate
synthetic boundary tests exercise traversal limits and protected descriptors.

## Kernel detector report rules — 2026-11-14

The ninth mode, `diagnose-stalls`, generates 501 invented mixed watchdog/blocked-task
reports and verifies 500 retained findings spanning all three new rules. Ten fresh
Linux/Python 3.14.4 children measured median wall 0.0581 s, maximum wall 0.0624 s,
median CPU 0.0512 s and maximum peak RSS 26.48 MiB. All nine modes passed the existing
<50 MiB RSS / <1 s CPU / <2 s wall budgets. The regression suite now runs two fresh
children per mode. These figures cover synthetic parsing/rendering, not real lockups,
detector overhead, journald latency or native Atop replay.

## Retained journal reconstruction — 2026-11-14

All diagnostic benchmark modes now include the retained-window summary and finding
positions. The tenth mode, `diagnose-clock`, verifies 500 mixed findings and 499
adjacent offset changes, retaining only 16 examples with explicit truncation.
Ten fresh Linux/Python 3.14.4 children measured median wall 0.0592 s, maximum wall
0.0629 s, median CPU 0.0520 s and maximum peak RSS 27.04 MiB. All ten modes passed
the existing <50 MiB RSS / <1 s CPU / <2 s wall budgets. Regression tests now run
two children per mode. The synthetic clock fixture changes data only, never system
time. Results exclude native tool startup, storage latency and real incident coverage.

## Explicit journal source scope — 2026-11-14

The eleventh mode, `diagnose-system`, uses a synthetic system-scope interface and
verifies 500 retained kernel records with completeness still unknown. Ten fresh
Linux/Python 3.14.4 children measured median wall 0.0541 s, maximum wall 0.0552 s,
median CPU 0.0472 s and maximum peak RSS 26.11 MiB. All eleven modes passed the
existing <50 MiB RSS / <1 s CPU / <2 s wall budgets. Regression tests now run two
children per mode. These measurements exclude native journalctl, real access checks
and filesystem latency; no group/permission changes or host logs are used.

## Targeted event search — 2026-11-15

The twelfth mode, `diagnose-events`, verifies 500 findings in each of two filtered
candidate sets plus 500 ordinary-tail findings, with both candidate caps explicitly
reached. Ten fresh Linux/Python 3.14.4 children measured median wall 0.0793 s, maximum
wall 0.0843 s, median CPU 0.0714 s and maximum peak RSS 31.59 MiB. All twelve modes
passed <50 MiB RSS / <1 s CPU / <2 s wall budgets. The resource regression suite now
runs two children per mode. Native whole-boot journal searching, disk I/O and access
checks are excluded; each actual external query has separate deadline/output limits.

## Unclassified candidate review — 2026-11-15

The thirteenth mode, `diagnose-review`, verifies 500 retained unclassified kernel
candidates, all-candidate counts and 20 newest examples with explicit truncation,
alongside the ordinary tail and structured candidate query. Ten fresh Linux/Python
3.14.4 children measured median wall 0.0761 s, maximum wall 0.0798 s, median CPU
0.0683 s and maximum peak RSS 29.00 MiB. All thirteen modes passed the existing
<50 MiB RSS / <1 s CPU / <2 s wall budgets. Tests now run two fresh children per mode.
Existing maximum matched-candidate mode also passed at 31.58 MiB peak RSS. No live
host messages, native journal search cost or actual warning semantics are measured.

## OverlayFS layer-reuse rule — 2026-11-15

The fourteenth mode, `diagnose-overlay`, verifies 500 retained findings from 501
invented upperdir/workdir warnings. Ten fresh Linux/Python 3.14.4 children measured
median wall 0.0583 s, maximum wall 0.0603 s, median CPU 0.0513 s and maximum peak RSS
27.43 MiB. All fourteen modes passed <50 MiB RSS / <1 s CPU / <2 s wall budgets.
Regression tests now run two fresh children per mode. No filesystem is mounted,
container started or live incident reproduced; native collection cost is excluded.

## Exact boot identity selection — 2026-11-15

The existing `diagnose-system` mode now selects its invented identity with --boot-id
and verifies ID-based resolution alongside 500 retained kernel records. Ten fresh
Linux/Python 3.14.4 children measured median wall 0.0562 s, maximum wall 0.0587 s,
median CPU 0.0492 s and maximum peak RSS 26.20 MiB. All fourteen modes passed the
existing <50 MiB RSS / <1 s CPU / <2 s wall budgets. Other modes continue to exercise
index/default selection. No native journal traversal or real reboot is measured.

## Historical receipt boundary — 2026-11-15

The existing system-scope mode now combines an invented boot ID with --until-us and
verifies the requested boundary and 500 retained kernel records. Ten fresh Linux/
Python 3.14.4 children measured median wall 0.0562 s, maximum wall 0.0584 s, median
CPU 0.0493 s and maximum peak RSS 26.23 MiB. All fourteen modes passed the existing
<50 MiB RSS / <1 s CPU / <2 s wall budgets. Other modes retain default latest-tail
collection. Native historical journal traversal and actual storage latency are excluded.

## Inclusive journal receipt ranges — 2026-11-15

The existing system-scope mode now combines --since-us and --until-us with an
invented boot ID and verifies both requested boundaries and 500 retained records.
Ten fresh Linux/Python 3.14.4 children measured median wall
0.0680 s, maximum wall 0.0815 s, median CPU
0.0583 s and maximum peak RSS 26.79 MiB. All fourteen modes passed
<50 MiB RSS / <1 s CPU / <2 s wall budgets. Native journal traversal, filesystem
latency and completeness of real incident evidence are excluded.

## Journal-driver loss observations — 2026-11-15

The fifteenth mode, `diagnose-journal-loss`, exercises 500 retained mixed structured
suppression and missed-kernel-message reports with the record cap explicitly reached.
Ten fresh Linux/Python 3.14.4 children measured median wall
0.0573 s, maximum wall 0.0595 s, median CPU 0.0502 s and
maximum peak RSS 27.29 MiB. All fifteen modes passed <50 MiB RSS / <1 s CPU /
<2 s wall budgets. Regression tests run two fresh children per mode. No real logging
flood, kernel loss or host journal is used; native collection cost is excluded.

## Historical CPU accounting — 2026-11-15

The existing `diagnose-atop` mode now verifies execution, idle, I/O-wait and steal
percentages for all 256 retained synthetic samples. Ten fresh Linux/Python
3.14.4 children measured median wall 0.0761 s, maximum wall 0.0791 s,
median CPU 0.0688 s and maximum peak RSS 27.84 MiB. All fifteen modes passed
<50 MiB RSS / <1 s CPU / <2 s wall budgets. Native replay cost, live contention and
actual recording accuracy remain outside these synthetic measurements.

## Integrated phase 2 and multi-boot overview — 2026-11-15

Two new modes verify the bounded end-to-end workflow: seven 501-record boot tails
reduced to summaries, and one combined diagnosis with targeted searches, receipt
bounds, Atop and both pstore sources. Ten fresh Linux/Python 3.14.4 children
per mode measured:

| Mode | Median wall s | Maximum wall s | Median CPU s | Maximum RSS MiB |
| --- | --- | --- | --- | --- |
| incidents | 0.0913 | 0.0974 | 0.0849 | 24.93 |
| diagnose-integrated | 0.1097 | 0.1113 | 0.1011 | 33.59 |

All seventeen modes passed <50 MiB RSS / <1 s CPU / <2 s wall budgets. Resource
regression tests run two children per mode. Native journal traversal, access checks,
recording decompression and kernel filesystem latency are excluded; external calls
retain their separate deadlines and byte limits. No real crash or host fixture is used.

## Extended resource context and final integrated run — 2026-11-15

The eighteenth mode exercises one complete maximum-cardinality extended sample:
32 disks, 32 interfaces and 256 paired processes. Integrated diagnosis now opts in
to extended resources alongside targeted journal search and both pstore sources.
Ten fresh Linux/Python 3.14.4 children per mode measured:

| Mode | Median wall s | Maximum wall s | Median CPU s | Maximum RSS MiB |
| --- | --- | --- | --- | --- |
| diagnose-extended | 0.0888 | 0.0905 | 0.0773 | 33.36 |
| diagnose-integrated | 0.1143 | 0.1169 | 0.1028 | 38.36 |
| incidents | 0.0901 | 0.0933 | 0.0836 | 24.96 |

All eighteen modes passed <50 MiB RSS / <1 s CPU / <2 s wall budgets. The synthetic
maximums measure parser/CLI overhead, not native replay or real recording compatibility.
Target-host qualification remains necessary; no real crash or load injection is used.

## Phase 3 network/security sampling — 2026-11-15

Two new modes each exercise 128 interfaces, measured short-interval rates and three
supported TCP counter-growth findings while attack assessment remains Unknown.
Ten fresh Linux/Python 3.14.4 children per mode measured:

| Mode | Median wall s | Maximum wall s | Median CPU s | Maximum RSS MiB |
| --- | --- | --- | --- | --- |
| network | 0.1016 | 0.1035 | 0.0412 | 24.24 |
| security | 0.1007 | 0.1031 | 0.0422 | 24.25 |

All twenty modes passed <50 MiB RSS / <1 s CPU / <2 s wall budgets. Network modes
include the real requested 0.05-second sleep but use invented counters; they generate
no traffic and exclude live procfs latency. CI runs two children per mode. Production
VPS accuracy, actual attack detection and distribution qualification remain unverified.

## SSH and local administrator evidence — 2026-11-15

The twenty-first mode combines 500 SSH findings/original records, 500 ordinary
journal records and both 500-candidate filtered views with local evidence enabled.
Ten fresh Linux/Python 3.14.4 children measured median wall
0.1320 s, maximum wall 0.1392 s, median CPU 0.1195 s and maximum
peak RSS 41.57 MiB. All twenty-one modes passed <50 MiB RSS / <1 s CPU /
<2 s wall budgets. CI runs two children per mode. Evidence and identities are invented;
native journal search latency and actual SSH detection accuracy are not measured.

## Atop administrator identities and replay evidence — 2026-11-15

Basic/extended replay now retains recorded hostnames and native sample lines. The
maximum extended mode also verifies 256 process/thread detail records, 32 named
disks and 32 named interfaces. Ten fresh Linux/Python 3.14.4 children measured:

| Mode | Median wall s | Maximum wall s | Median CPU s | Maximum RSS MiB |
| --- | --- | --- | --- | --- |
| diagnose-atop | 0.0788 | 0.0828 | 0.0713 | 28.32 |
| diagnose-extended | 0.0969 | 0.1017 | 0.0836 | 33.93 |
| diagnose-integrated | 0.1247 | 0.1356 | 0.1117 | 38.56 |
| diagnose-ssh | 0.1171 | 0.1201 | 0.1065 | 41.64 |

All twenty-one modes passed <50 MiB RSS / <1 s CPU / <2 s wall budgets. The existing
combined SSH/admin view remains covered. These are invented sources and parser/CLI
measurements, not native replay or target-host qualification. No host identities or
recordings are committed or uploaded.

## Pstore local administrator content views — 2026-11-15

Live/archive modes now retain source paths, observed file metadata and lossless
content. Each source fixture contains eight invented records totaling 512 KiB.
Ten fresh Linux/Python 3.14.4 children per mode measured:

| Mode | Median wall s | Maximum wall s | Median CPU s | Maximum RSS MiB |
| --- | --- | --- | --- | --- |
| diagnose-pstore | 0.0632 | 0.0678 | 0.0559 | 28.14 |
| diagnose-pstore-archive | 0.0637 | 0.0652 | 0.0564 | 28.13 |
| diagnose-integrated | 0.1232 | 0.1289 | 0.1113 | 41.82 |

All twenty-one modes passed <50 MiB RSS / <1 s CPU / <2 s wall budgets. Integrated
coverage includes both maximum-sized sources alongside journal/search/Atop analysis.
No host crash files are used; actual firmware/backend latency, non-atomic filesystem
behavior and supported-target qualification remain outside synthetic measurements.

## Firewall-labelled kernel reports — 2026-11-15

The twenty-second mode verifies 500 firewall reports/original candidates alongside
500 SSH candidates, both existing filtered queries and ordinary journal evidence.
Ten fresh Linux/Python 3.14.4 children measured median wall
0.1402 s, maximum wall 0.1442 s, median CPU 0.1290 s and maximum
peak RSS 48.25 MiB. All twenty-two modes passed <50 MiB RSS / <1 s CPU /
<2 s wall budgets. Ordered field pairs and compact timeline references avoid copying
packet context into every timeline entry. All traffic/logs are invented; native
journal latency, real firewall behavior and attack detection are not measured.

## Optional socket snapshot — 2026-11-15

The `network-sockets` mode renders 512 invented TCP socket rows alongside 128
synthetic interfaces through the real JSON CLI, with ten fresh children. Median
wall time was 0.1069 s (maximum 0.1083 s), median CPU 0.0498 s and maximum RSS
25.47 MiB on Linux/Python 3.14.4. All 23 modes passed their regression budgets.
These figures exclude real ss startup, procfs/netlink contention and host load;
the external-command deadline/output cap remain independent runtime controls.

## Phase 3 integrated security acceptance — 2026-11-15

The `phase3-security` mode uses both 500-candidate synthetic log sources and six
contiguous extended Atop samples with 32 interfaces. It validates all independent
source states, historical comparison, derived findings and explicit finding cap,
rendering the real JSON CLI. Ten fresh children measured median wall 0.1532 s
(maximum 0.1596 s), median CPU 0.1359 s and maximum RSS 46.81 MiB on
Linux/Python 3.14.4. All 24 modes passed <50 MiB RSS / <1 s CPU / <2 s wall.
This is a bounded synthetic regression, not a live attack detector calibration or
a guarantee for every host. Native source execution and journal I/O are excluded.

## Phase 4 terminal frontend and constrained profiles — 2026-11-15

Two fresh-process modes collect through the actual session model and draw real
frontend viewports using an invented screen. No terminal screenshots or host
evidence are committed. `tui-diagnostic` retains 500 ordinary journal originals,
both bounded security-log sources, six extended Atop samples/32 interfaces, and
both 512 KiB synthetic pstore sources. The browser keeps references to one report;
it does not build a second full JSON rendering to display a viewport.

Ten-child measurements on Linux/Python 3.14.4:

| Mode | Median wall | Max wall | Median CPU | Max RSS |
| --- | ---: | ---: | ---: | ---: |
| tui-status | 0.1716 s | 0.1739 s | 0.0582 s | 29.20 MiB |
| tui-diagnostic | 0.1290 s | 0.1373 s | 0.1149 s | 38.96 MiB |

All 26 CLI/TUI modes passed the <50 MiB RSS / <1 s CPU / <2 s wall budgets.
A native local PTY run completed one ordinary status refresh and restored the
terminal on quit, measuring 23.52 MiB peak child RSS. This is a development-host
observation, not an SSH/VPS or native journal/Atop I/O guarantee.

The separate `scripts/vps_acceptance.py --iterations 3` completed 45 synthetic
fresh-process runs across one-CPU-affinity profiles with 128/256/512 MiB virtual
address-space limits. All passed the same regression budgets; maximum RSS was
46.29 MiB. RLIMIT_AS is not VM RAM or a cgroup memory quota. These results do not
claim a booted target VPS, all distro versions, remote SSH behavior or production
acceptance. See [release acceptance](release-readiness.md).

## Reading performance and constrained-test output

The default benchmark and VPS-process-profile output is now a short text summary
with pass/failure counts, resource limits and investigation pointers. It does not
imply real-server workload or actual VM deployment acceptance. Per-scenario/per-run
measurements remain available explicitly:

```sh
python3 scripts/benchmark.py --iterations 10 --details
python3 scripts/benchmark.py --iterations 10 --json
python3 scripts/vps_acceptance.py --iterations 3 --details
python3 scripts/vps_acceptance.py --iterations 3 --json
```

Automation that parsed the former default JSON must now request `--json`; its schema
is unchanged. Internal worker responses remain JSON, and the consolidated server
checker explicitly requests JSON from these tools. No measurements or budget rules
are removed by the shorter display.

## Explained CLI/TUI result views — 2026-11-15

The TUI modes now also render their source-page explanation before navigating the
raw report. Guidance groups normalized findings and holds references to original
objects without copying evidence. Ten fresh children on Linux/Python 3.14.4 measured
`tui-status` median wall 0.1719 s (maximum 0.1731 s), median CPU 0.0575 s and peak
RSS 29.38 MiB; `tui-diagnostic` median wall 0.1303 s (maximum 0.1328 s), median CPU
0.1158 s and peak RSS 39.04 MiB. All 26 modes passed their existing budgets.
These are synthetic frontend regressions, not proof of production deployment,
attack calibration or native journal/recording I/O performance.

## Corrected Textual workspace — 2026-11-15

Earlier curses rendering numbers above are historical and do not measure this
frontend. Ten fresh processes per mode passed all 26 modes. On Linux/Python 3.14.4,
`tui-status` median wall time was 0.5975 s (maximum 0.6021 s), median CPU 0.3160 s
and peak RSS 52.37 MiB. `tui-diagnostic` median wall was 0.5599 s (maximum 0.5825 s),
median CPU 0.4014 s and peak RSS 63.18 MiB. These modes mount the real Textual
widgets and open/close a record dialog with synthetic bounded data.

The optional frontend has an explicit 80 MiB regression bound; the core CLI retains
50 MiB. CPU remains below one second and fresh wall time below two seconds. All
45 one-CPU-affinity runs across 128/256/512 MiB address-space ceilings passed; peak
RSS was 62.89 MiB. These ceilings describe a process, not a VM RAM requirement or
real SSH/server acceptance.

## Milestone 1 current-server views — 2026-11-16

All 28 modes passed ten fresh-process runs on Linux/Python 3.14.4 with the existing
50 MiB CLI / 80 MiB Textual, <1 s CPU and <2 s wall budgets. New `health` and
`tui-health` modes retain 128 invented failed services with long descriptions; the
Textual mode opens their actual paged source table.

| Mode | Median wall | Max wall | Median CPU | Max RSS |
| --- | ---: | ---: | ---: | ---: |
| health | 0.1494 s | 0.1526 s | 0.0398 s | 24.45 MiB |
| tui-health | 0.5956 s | 0.7193 s | 0.3479 s | 53.70 MiB |
| tui-status | 0.5806 s | 0.5982 s | 0.3170 s | 51.63 MiB |
| tui-diagnostic | 0.5610 s | 0.5821 s | 0.4029 s | 63.18 MiB |

All 63 constrained synthetic runs passed across one-CPU-affinity
and 128/256/512 MiB virtual-address-space profiles; maximum RSS was
62.95 MiB. These are process regression
checks, not actual VM RAM requirements or target-server/SSH acceptance. Native tool
startup, real storage latency and real incident coverage remain outside these fixtures.
