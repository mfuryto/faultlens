# Foundation resource benchmarks

Run from a trusted source checkout on Linux with Python 3.11+:

```sh
python3 scripts/benchmark.py --iterations 10
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

The unittest suite measures two children per command and checks deliberately loose
regression budgets: <50 MiB peak RSS, <1 s CPU and <2 s total wall per invocation.
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
