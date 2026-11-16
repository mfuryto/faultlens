# Milestone 1 — current-server decision views

Design recorded before implementation, 2026-11-16. Active scope is System, Health
and Network. General security/CVE assessment is a possible future roadmap extension,
not part of this milestone. Operator acceptance is pending.

## Primary screen contracts

All examples are invented. The same decision model drives readable CLI and TUI;
JSON retains original observations and adds source results without removing fields.
Raw values, all interfaces and original native rows remain accessible in details.

| Section | Normal example | Attention example | Unavailable example |
| --- | --- | --- | --- |
| System | CPU 20%, RAM 50%, root capacity 60%; no configured capacity warning; no immediate change indicated | Root filesystem 96%: capacity critical under existing 95% rule; review space/retention before deleting. A high one-shot CPU sample merits review, not a sustained-overload diagnosis | Explain which readings are unavailable and what can still be measured; never substitute zero or a healthy status |
| Health | Operational checks and diagnostic readiness shown separately; manager running and no failed service rows observed | List observed failed service units; separately explain absent previous-boot visibility or an inactive optional recorder | Distinguish no explicit setting, unsupported expression, unavailable tool/data and missing observations. Unverified defaults are informational, not configuration faults |
| Network | Explain sampled activity/rates and error-counter behavior; show a small relevant subset with all retained interfaces reachable | Prioritize observed error/drop growth and noncomparable interfaces; explain impact and follow-up without identifying an attack or physical failure | Separate invalid/reset/missing comparisons from zero activity; keep independently available protocol/socket evidence useful |

The primary screen contains a short answer, a next step, and rows with Check,
Result, Assessment and Meaning/next step. Detail dialogs retain full explanations,
collection confidence, scope and originals. Assessment is a view decision, not a
rewrite of source evidence.

## Source inventory and decisions

- System: existing procfs/statvfs/system-manager observations. Capacity warnings use
  existing thresholds. CPU >=90% is an explicitly disclosed short-sample review hint;
  load, swap use and accumulated counters do not acquire invented severity thresholds.
  An observed zero unreserved bytes on a log filesystem is a readiness review hint;
  reserved space/writer access and actual recording success remain unverified.
- Health: collect the existing current-system snapshot plus readiness observations.
  Keep the `check` command as the readiness-only operation. Health's CPU sample follows
  the existing duration setting. Existing preservation choice still controls deeper
  recording/retention checks. No settings schema change is needed.
- Missing service context: add one fixed read-only systemctl failed-service listing.
  Existing trusted-tool lookup, controlled environment, 2-second/256-KiB capture limits
  apply; parse at most 128 units and 4096 bytes per line. Unsupported/nonzero/over-limit
  output is unavailable, never an empty success. No unit-derived command is executed.
- Network: use original paired interface/protocol snapshots and optional ss results.
  Show at most three interface examples, prioritizing error/drop growth and comparison
  gaps before traffic activity. Idle/remaining interfaces are grouped with explicit
  counts; all rows remain in a paged domain table. Never sum virtual/physical layers.
- Interface roles/routes and live per-process resource attribution are not currently
  collected. This milestone will not guess them from names or counters. They remain
  explicit limitations; add another collector only if this contract cannot be useful
  without it. No new route lookup, network probe, package or daemon is justified here.

## Acceptance evidence required

- Normal/review/unavailable examples for all three views, defaults versus missing data,
  independent service failure/readiness gaps and hostile native rows.
- Many-interface examples preserve every original while the main screen stays bounded.
- CLI/TUI agree on meaning; compact terminals keep readable values/assessments and
  details; navigation, automatic reads, cancellation and saved preferences still work.
- Existing content/workflow policy, resource budgets and required GitHub checks pass.
- Supply actual rendered synthetic previews and ordinary-user native summary evidence;
  keep target-server/operator acceptance distinct from automated verification.

## Implementation and review evidence

The current implementation shares the decision model across readable CLI and the
actual Textual workspace. Original readings, interfaces, source rows and confidence
remain available through details/JSON. The readiness-only `check` command remains
separate from operational `health`.

- Python 3.14.4: 504 automated tests passed, including the nine normal/review/gap
  screen scenarios, source boundaries and retained-original checks.
- Python 3.11: the same 504 tests passed in an offline, read-only container with
  hash-locked frontend dependencies, one CPU and a 512 MiB memory ceiling.
- Repository policy and Gitleaks tree/reachable-history scans passed with no leaks.
- All 28 benchmark modes and 63 constrained-process runs passed existing budgets;
  see [measurements](../benchmarks.md#milestone-1-current-server-views--2026-11-16).
- Ordinary-user native System/Health/Network queries completed on the development
  host, including the new service source and optional socket source. Only counts
  and source states were examined; host records are not committed.
- Rendered synthetic previews: [System](../previews/workspace-system.svg),
  [Health](../previews/workspace-health.svg), [Network](../previews/workspace-network.svg).
  These are invented examples, not diagnostic data from an operator server.

Operator usefulness, real SSH navigation and supported-server acceptance are pending.
Automated checks and a merge do not close that acceptance gate or start milestone 2.
