# Incident time selection and consistent journal scope

Design recorded before implementation, 2026-11-16. This is the remaining time-selection
work inside milestone 2, not an unrelated feature or a claim of operator acceptance.

Allow an administrator to enter an explicit date/time with UTC or a numeric offset,
for example `2026-11-14T23:20:00+01:00`. CLI adds --since/--until; existing --since-us
and --until-us remain exact nonnegative Unix microsecond options. The TUI accepts
both and displays normalized UTC dates. Reject relative, timezone-free, malformed,
sub-microsecond or out-of-range input before collection. Use integer arithmetic;
never change the clock, infer local timezone or round epoch boundaries through floats.
Persist existing numeric strings under the unchanged settings schema.

The same inclusive receipt-time bounds apply to the ordinary tail, both broader
kernel/systemd event queries, SSH and firewall searches. Bound the native query
before the 501-record sentinel and independently reject any out-of-range response,
including a sentinel. A rejected query retains no successful prefix and never falls
back to a whole-boot search. Without bounds, existing whole-selected-boot behavior
is unchanged. Source scope explicitly records both boundaries and completeness unknown.

Atop remains a separately labeled two-hour window anchored to the last retained
journal receipt in one date-named recording. Pstore fragments remain unattributed;
neither source is falsely presented as scoped to the selected journal time range.

Tests cover timezone equivalence, exact microseconds, leap/date/range errors,
ambiguous inputs, invalid edits preserving preferences, native fixed arguments,
inclusive boundaries, sentinels, out-of-range responses and all source scopes.
Actual CLI and Textual workflows must show human-readable settings and scope.
Run the existing security, cross-Python and resource checks. Server/SSH usefulness
acceptance remains pending; no release is authorized by this work.

## Rendered checks

Actual Textual renders with invented data show the
[date/time editor](../previews/incident-time-edit.svg) and the
[selected investigation scope](../previews/incident-time-scope.svg).
The Settings table normalizes entered offsets to UTC; complete source references
and raw evidence remain unchanged. These are synthetic examples, not host incidents.

## Verification

- All 524 tests passed on Python 3.14.4 and Python 3.11, including nine dedicated
  incident-time scenarios. The final targeted scenarios also verify partial-query
  gaps after an out-of-range response. Python 3.11 ran offline in a read-only container
  using the reviewed hash-locked frontend environment.
- All 28 benchmark modes passed ten iterations and all 63 constrained-process runs
  passed existing budgets; see [resource measurements](../benchmarks.md#incident-time-selection--2026-11-16).
- The final diff, repository security policy and Gitleaks tree/reachable-history scans
  passed. No real host evidence is committed.
- Actual target-server/SSH usefulness acceptance remains pending. Enter the incident
  period in Settings, collect Diagnostics using existing journal access, and verify
  that displayed messages and source gaps correspond to the requested period.
