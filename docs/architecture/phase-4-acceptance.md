# Phase 4 completion and acceptance

Reviewed: 2026-11-15. **Implementation and automated frontend acceptance are complete.**
This closes the TUI, navigation and readable-results engineering phase. It does not
certify a production deployment or authorize a license, package, tag or release.

## Delivered scope

| Area | Complete implementation | Boundary retained |
| --- | --- | --- |
| Terminal frontend | Eight keyboard-driven pages, wide/compact layouts, explicit refresh, resize and terminal restoration | Python curses/PTY required; CLI remains independent; no background polling |
| Readable results | Shared meanings, next steps, confidence and limits for readings, findings, boot summaries, interfaces, sockets, Atop samples and crash fragments | No healthy/secure verdict from missing or unmatched evidence; exact originals remain available |
| Source navigation | Immutable boot selection, source-scoped timelines, finding-to-evidence links, raw metadata access and reference-based browsing | No cross-query substitution, guessed identity, changed confidence or causal timeline across boots |
| Search and settings | Literal current-view search, next/previous matching rows/lines, typed session-only options and stale-scope notices | No filtering/redaction, regular expressions, shell execution, persistence or implicit collection |
| Reporting contracts | Readable CLI, copyable optional commands, technical --details and unchanged --json models; full TUI raw trees | No output parsing contract for prose; no automatic export/upload or privacy masking |
| Resource validation | Bounded source fixtures, fresh-process benchmarks, one-CPU constrained profiles and real PTY lifecycle tests | Process/address-space constraints are not real VM RAM or distro deployment certification |
| Release preparation | Source launch/update instructions, operator test script, dependencies, threat model, publication checklist and release gates | No license selected, distribution built or release published |

The final integration closes interface rate/reset explanations, prevents suggested
commands from being hard-wrapped into multiple shell lines, and supplies a complete
synthetic session across all eight pages. Missing/decreased counters are never zero
traffic; actual measured batch timing controls rates. Error/drop details remain in
per-interface technical views, with positive growth highlighted in readable CLI output.

## Architecture and safety

The specification prefers prompt_toolkit but permits an alternative. Python curses
provides the Linux terminal lifecycle without a pip dependency; the application owns
a bounded menu/tree model. See [Python curses](https://docs.python.org/3.11/library/curses.html)
and the [curses lifecycle](https://docs.python.org/3.11/howto/curses.html).

`tui_model` owns session settings, source dispatch, one report and reference-based
navigation. `tui` owns layout, key handling and a bounded ASCII editor. Presentation
modules explain retained models without collecting sources, changing thresholds or
copying evidence trees. `curses.wrapper` restores terminal attributes on exit/errors;
Ctrl-C exits with 130. Optional sources default off and never elevate privileges.
Old reports/navigation references are dropped before explicit refresh. Idle input
blocks; there is no timer, daemon, database, telemetry or external service.

Original administrator evidence remains inspectable. Terminal controls are escaped
reversibly. Raw source messages never acquire trusted finding/navigation roles merely
because they resemble diagnostic JSON. Local evidence can be incomplete or falsified;
root/kernel compromise, source bounds, unknown attribution and native filesystem calls
without a hard deadline remain explicit limits.

## Reproducible verification

Run as the checkout owner:

```sh
python3 -m unittest discover -s tests -q
python3 scripts/security_check.py
python3 scripts/benchmark.py --iterations 10
python3 scripts/vps_acceptance.py --iterations 3
python3 scripts/server_check.py --live-only
```

Synthetic acceptance covers all pages, explicit refresh, settings validation, stale
scope, unavailable/empty/partial sources, record caps, RESET and missing measurements,
confidence, source identity, safe commands, complete originals, raw roles, long values,
search, compact/resized layouts and normal/interrupt terminal restoration. The native
operator check reports available coverage and limitations; it never certifies health.

Benchmarks exercise maximum bounded journal/security/socket/interface evidence,
recording/crash readers and actual frontend navigation/rendering. Constrained profiles
use one allowed CPU and 128/256/512 MiB virtual-address-space limits for five modes;
they do not boot Debian/Ubuntu images or constrain total host RAM.

Closeout verification on the development host:

| Check | Result |
| --- | --- |
| Complete unit/integration/PTY suite | 446 tests passed |
| Fresh-process benchmarks | All 26 cases passed over 10 iterations; integrated TUI peak RSS 39.50 MiB |
| Constrained process acceptance | All 45 runs passed across three address-space ceilings, five modes and three iterations |
| Read-only native operator check | 54 PASS, 0 WARN, 15 MISSING, 11 SKIP, 0 FAIL |
| Repository security and secret checks | Baseline, diff checks and working-tree/history Gitleaks scans passed |

Native MISSING/SKIP results cover unverified journal assignments, unavailable system
journal/usable authentication-firewall evidence, optional unrequested historical/crash
sources, the noninteractive terminal and repository groups intentionally skipped by
--live-only. Repository tests were run separately. These are coverage limits, not
evidence of a healthy host or completed target-server acceptance. No host evidence,
names, logs or endpoint captures are included in this record.

## Remaining deployment and release gates

The following are outside completed software acceptance and remain open:

- Operator navigation in the actual server's SSH terminal and representative sizes;
  ordinary/admin access, retained recordings and unavailable sources must be checked
  on the deployment host using the [server test guide](../server-check.md).
- Actual selected Debian/Ubuntu releases and at least one small one-CPU VPS still
  require recorded acceptance. Development-host checks and constrained processes
  are not a substitute. Detector calibration needs labeled data before accuracy claims.
- The owner must select/approve a license, support/version policy and exact release
  artifacts before distribution. No publication is authorized by passing checks.

See [readable results](../readable-results.md), [TUI controls](../tui.md),
[resource measurements](../benchmarks.md) and [release readiness](../release-readiness.md).
No new manual GitHub setting is required by this closeout; existing required security
checks and the solo-maintainer merge policy remain in force.
