# Phase 1: local CLI foundation

Status: first implementation, pre-release. This is not the full system-status module
or a supported incident analyzer. No license has been selected.

## Decisions and dependency strategy

1. Use Python 3.11+ and its standard library for the foundation. `argparse`, `json`,
   `dataclasses`, `selectors`, `subprocess`, and `unittest` meet current requirements.
   No runtime or build packages, installation step, lockfile, network client, daemon,
   database, or persistent report store are introduced. The source-checkout launcher
   is deliberate; distribution packaging is deferred until packaging/license review.
2. Prefer Linux's existing interfaces over reimplementing monitoring infrastructure.
   Read documented `/proc` counters and root `statvfs`, then query optional systemd
   tools through a fixed read-only catalog. Missing integrations affect only their
   observations. Do not add psutil just to wrap these few bounded reads; reconsider it
   if maintained platform handling would eliminate substantial custom code later.
3. Keep `prompt_toolkit` as the preferred future TUI candidate. It is unnecessary for
   phase 1. The CLI, parsers and observations must remain independent of the TUI.
   Evaluate pinned versions, provenance and licenses before adding any dependency.
4. Do not gather raw journal messages, process command lines, addresses, hostnames,
   packet captures, or full diagnostic reports. Dependency/logging checks query
   presence, service state and visible boot metadata only. No logging configuration
   or system setting is changed. No application file logger is enabled.
5. Keep reusable parsers separate from OS access so synthetic tests can exercise
   malformed evidence and denied access without collecting from the CI host.

## Module boundaries

| Module | Responsibility |
| --- | --- |
| `models.py` | Versioned JSON observation schema, source, confidence and limitations |
| `linux.py` | Bounded known-file reads, root filesystem capacity and visible PID count |
| `parsers.py` | Pure validation and normalization of documented counters |
| `commands.py` | Fixed argv catalog, trusted executable resolution, controlled environment, deadlines and output caps |
| `collectors.py` | Compose observations and expose unavailable evidence without inventing values |
| `cli.py` | Arguments, JSON/plain rendering and terminal control neutralization |
| `scripts/benchmark.py` | Fresh-process synthetic startup, CPU and peak RSS measurements |

There is no mutation boundary implementation because no mutations are supported.
Future configuration support must implement a separate preview/confirmation/rollback
boundary rather than extending read-only command arguments.

## Interfaces and evidence semantics

- Aggregate CPU is sampled twice, 0.1 second apart by default (CLI range 0.05–1).
  Sum the first eight CPU counters; exclude idle and iowait from busy time and avoid
  double-counting guest fields. Reject a non-advancing or decreasing sample. The
  estimate includes steal time and is not a per-process metric or diagnosis.
- `/proc/loadavg` reports 1/5/15-minute load. Load includes uninterruptible tasks;
  it is not CPU usage. No unsupported overload threshold is applied.
- RAM usage is `MemTotal - MemAvailable`. Missing MemAvailable remains unavailable;
  do not substitute MemFree or imply the kernel's estimate is exact. Swap may be zero.
- Kernel release, uptime and boot time are reported with explicit sources. Kernel
  counters can reflect the host rather than cgroup limits; phase 1 is not a
  container-capacity monitor. Event correlation must account for clock changes.
- `statvfs(/)` covers only the root filesystem. Reserved blocks reduce ordinary
  users' available space. `filesystem.root.used` remains the allocated percentage
  of total capacity; `filesystem.root.user_used` uses allocated plus user-available
  space as its denominator, matching df's reserved-block semantics before df's
  whole-percent ceiling. Capacity is not filesystem integrity or disk health.
- `/proc/diskstats` sectors are converted using 512-byte accounting units. Device
  and partition counters overlap; do not sum them or infer rates from one sample.
- `/proc/net/dev` reports cumulative counters in the current network namespace.
  It does not imply throughput, connection counts, DDoS, or interface link health.
- PID directory count is a bounded, inherently racy overview; no process names,
  arguments or environment variables are collected.
- `systemctl is-system-running` can return a nonzero code for a valid degraded state.
  Only documented state tokens are accepted; raw stdout/stderr is never displayed.
- `journalctl --list-boots` counts prior visible boot indices. Directory existence,
  a running service, and zero visible prior boots do not prove persistence settings,
  sufficient retention, complete history or lack of historical events. Journal access
  depends on permissions. Do not automatically recommend running everything as root.
- Atop availability and service state do not prove that samples are being recorded.
  Sampling intervals, retention, disk budgets, journal configuration precedence,
  pstore usability and historical security coverage remain phase 2 verification work.

Memory and root capacity observations use warning >=90% and critical >=95% before
display rounding, disclosed
in JSON. These are initial generic thresholds, not workload-specific incident rules.
Other raw measurements have no invented warning thresholds. `normal` means the stated
observation was read and has no configured warning; it does not certify host health.
Confidence describes the observation, never a confirmed root cause. Null/unavailable
is different from numeric zero. JSON schema version 1 includes timestamps, units,
state, confidence, explanation, source, limitations and applied thresholds. Reads
are sequential rather than atomic; collected_at marks report completion.

## Security and resource budgets

Reads are capped at 256 KiB (kernel release 256 bytes); symbolic-link final components,
non-regular files, invalid UTF-8 and oversized sources are rejected. Known Linux
parent paths are trusted; this is not a general untrusted-directory filesystem API.
Enumeration caps: 128 interfaces/devices and 32,768 `/proc` entries. Crossing a cap
marks the affected observation unavailable instead of silently truncating evidence.

External commands use trusted root-owned non-group/world-writable executable paths
and ancestors, fixed argv, no shell, no implicit sudo, no inherited user environment,
no stdin or pagers, a two-second deadline and a combined stdout/stderr cap of 256 KiB.
The process group is killed on timeout/output overflow; raw errors are not printed.
A compromised root user/kernel remains outside this integrity guarantee. Synchronous
kernel filesystem calls can still stall on a malfunctioning host and are not covered
by the subprocess deadline. `check` can take approximately six seconds if all three
external queries hit their individual deadline; status can take sample time + two
seconds. There is no background polling or automatic report exposure.

Performance regression budget for fresh synthetic CLI processes: peak RSS <50 MiB,
CPU <1 second and total wall time <2 seconds per invocation. These intentionally
loose shared-runner limits detect regressions, not production service-level targets.
Tests/benchmarks use invented source data and fake command results. No live host
collection, evidence file or raw report is committed or uploaded by CI. A local live
smoke test is separate from reproducible tests and cannot establish distribution-wide
compatibility or worst-case performance.

## Deferred scope

Historical incident reconstruction, diagnostic root-cause rules, kernel warning
analysis, top per-process resource usage, all-mount discovery, interface link state,
connection/security analysis, historical rates, TUI, packaging and configuration
changes remain future work. Avoid presenting these as completed phase 1 features.
Test the first collectors on actual supported Debian/Ubuntu hosts and small VPSs
before claiming production support or confirming the resource targets there.

## Primary interface references

- [Linux proc documentation](https://docs.kernel.org/filesystems/proc.html)
- [Linux disk I/O statistics](https://docs.kernel.org/admin-guide/iostats.html)
- [journalctl boot listing](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- [systemctl state and exit behavior](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)
- [Python subprocess](https://docs.python.org/3/library/subprocess.html)

Optional reference-tool validation is documented in [measurement validation](../validation.md).

The first journal-only historical milestone is now documented in [Phase 2](phase-2-journal.md); remaining historical scope is listed there.
