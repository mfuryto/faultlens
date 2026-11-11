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
