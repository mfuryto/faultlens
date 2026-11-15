# Phase 2 implementation and acceptance review

Reviewed: 2026-11-15. The bounded, read-only historical CLI baseline is implemented.
This is an engineering milestone, not a claim that every incident can be reconstructed,
all product requirements are complete, or supported targets have passed deployment
acceptance. Faultlens remains pre-release. No license or publication decision changes.

## Delivered baseline

| Phase 2 priority | Implemented behavior | Evidence and boundary |
| --- | --- | --- |
| Persistent journal history | Scope-specific history, preservation assessment and explicit configuration/retention hints | Config values are not loaded-state proof; portable cat-config ignores commented defaults |
| Atop historical measurements | Opt-in fixed recording, bounded CPU/memory/swap replay, CPU accounting, optional disk/network/process context and temporal pairing | Host/boot unverified; interval averages and snapshots do not establish causes |
| Boot sessions and shutdown investigation | Stable index-to-ID selection, exact IDs and up to seven boot summaries | Initiation markers are distinguished from completion; normal/unexpected outcome remains Unknown without sufficient evidence |
| Chronological reconstruction | Boot-local monotonic timelines, receipt-time ranges, clock variation and coverage metadata | Retained records only; no whole-boot completeness or cross-boot causality claim |
| Evidence-backed diagnostic rules | OOM/panic/I/O/ext4/systemd/stall/OverlayFS reports, journal loss, separate candidate review and optional pstore evidence | Narrow tested signatures; confirmed reports are not confirmed causes |

See [multi-boot overview](phase-2-overview.md), [journal analysis](phase-2-journal.md),
[Atop](phase-2-atop.md), [preservation](phase-2-preservation.md) and linked milestones
for exact collection contracts. The product specification remains the broader target;
this review does not silently remove its requirements.

## Acceptance procedure

Run tests and repository checks as the checkout owner, without root:

```sh
python3 -m unittest discover -s tests -q
PYTHON_COLORS=1 python3 -m unittest discover -s tests -q
python3 scripts/security_check.py
python3 scripts/benchmark.py --iterations 10
```

Integrated synthetic acceptance exercises check/history/incidents and one diagnosis
combining exact boot ID, system scope, both receipt boundaries, targeted search,
extended Atop and both pstore sources. Optional-source failures preserve journal findings.
CI never reads host journals, induces crashes/log flooding or uploads diagnostics.

On each target, use existing journal permissions. These commands are read-only;
there is no automatic elevation, group change or configuration change:

```sh
./bin/faultlens check --history
./bin/faultlens history --system-journal
./bin/faultlens incidents --system-journal --boot-count 3
./bin/faultlens diagnose --previous-boot --system-journal --json
```

Optional Atop/pstore smoke tests require existing locally available evidence and
explicit flags. Do not manufacture a crash or share raw recordings to satisfy an
acceptance check. Review normalized output locally before sharing even metadata.

## Verification status and open scope

| Environment / claim | Status |
| --- | --- |
| Synthetic parsers, rules, combined-source flow and seven-boot resource bounds | Automated regression coverage; see benchmarks for actual measurements |
| Development Ubuntu 26.04 / Python 3.14 | Local unit/resource verification and read-only native overview/configuration smoke |
| Earlier user-host Atop 2.12.1 / system journal / empty pstore archive | Limited manual observations; no complete crash ground truth or release qualification |
| Debian 12/13 and Ubuntu 22.04/24.04 deployment acceptance | Not performed; documentation/API compatibility is not equivalent to execution |
| Python 3.11 runtime and small resource-constrained VPS qualification | Not performed locally; no alternate interpreter or target provided |
| Actual freeze, clean-shutdown completion and lost-evidence ground truth | Not established; no destructive production fault injection |

The optional [extended Atop profile](phase-2-atop-extended.md) now supplies reported
disk/network counters and aggregate process resource history. Full process identity
and blame attribution, complete evidence browsing, cursor pagination, stronger source
identity, additional signatures and richer correlation remain open. Network/security analysis and TUI belong to later planned phases.
Native extended replay and small-VPS/distribution acceptance still require target
validation. No automatic configuration writer, export, daemon or database is added.

Do not describe this baseline as complete support for every historical requirement
or a production-ready release. A future release gate must resolve target validation
and explicitly decide the remaining product scope; green CI cannot establish those
facts. In particular, never replace Unknown with an unsupported reboot cause merely
to make a phase appear complete.
