# Problem-centered investigation workflow

Owner-approved priority correction, 2026-11-18. The primary entry must describe the
problem or time, not require administrators to select a boot first.

| Entry | Sources | Boundary |
| --- | --- | --- |
| Problems now | Current operational/resource and network snapshots plus the last 15 minutes of accessible journal evidence | Current readings are never backdated or treated as the cause of an earlier report |
| A selected period | Journal tail and requested fixed event/SSH/firewall searches with the same explicit UTC bounds, across all accessible boots unless filtered | Both boundaries required; a receipt time is not necessarily an event time |
| Before restart | Most recent visible previous boot, or an explicit optional boot filter | Retained last records are not verified incident, power-off or shutdown boundaries |

`investigate` is the primary CLI command. `--mode now`, `--mode period` and
`--mode before-restart` select the entry; supplying time boundaries implies period.
`--boot`/`--boot-id` are optional filters. The existing `diagnose` command remains
a single-boot technical reader for compatibility and evidence drill-down.

The TUI exposes the three actions directly in Investigate and links current-server
views to Problems now. Time selection is atomic: invalid/reversed edits cannot save
half a range. The selected mode, period and optional filter are visible with results.
History remains an optional source browser, not the required start of every inquiry.

Native window queries retain existing fixed executables, validated arguments,
two-second command bounds and 262144-byte/501-record capture. Each requested query
has a global 500-retained-record cap across boots, not a fresh allowance per boot.
At most seven boot partitions are interpreted. Caps, invalid/unavailable queries and
omitted partitions remain explicit coverage gaps. Captured records from partitions
not interpreted remain available as labeled raw originals; no fault verdict is
assigned to them. No first/last-record timestamp is
used to assume that a boot cannot contain other records in the requested range.

Partition records by their actual validated boot identity before applying existing
single-boot interpretation and reference resolution. Unknown relative boot indices
remain unknown. Never sort different boots by monotonic time or pool their counters
into a causal timeline. Findings and originals retain their source report context.
Atop replay needs an explicit date; multi-boot scope requires a narrower filter for
that optional correlation. Crash evidence is independent and never boot-attributed.

Preference schema migration retains previous selections and explains their legacy
scope. Fresh administrator defaults open Problems now with no boot filter. Explicit
primary actions start an unfiltered inquiry; the user may then add a filter. Saved
period boundaries apply only to period mode. No preference or source is silently
reset to manufacture successful results.

Acceptance requires current problems without a restart, a period crossing a restart,
explicit pre-restart selection, optional filter/clear behavior, partial/unavailable
sources, safe query construction, original reference isolation, CLI/TUI agreement,
atomic time validation, preference migration and the unchanged security/resource
gates. Real-server usefulness and second-server acceptance remain separate.

Local verification on 2026-11-18: 567 tests passed in the development environment
and the pinned Debian/Python 3.11.18 container. All six native contracts passed in
the frontend-absent/reviewed configurations, including an unfiltered primary period
query. Missing system journal evidence was reported as unavailable, without a
no-fault claim. Required CI still gates the exact PR head before merge; these
results do not establish owner/second-server acceptance.
