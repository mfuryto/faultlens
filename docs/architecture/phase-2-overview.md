# Phase 2: bounded multi-boot incident overview

`faultlens incidents` summarizes the newest three visible previous boots by default.
Use --boot-count 1 through 7 to select a smaller/larger bounded review. Current boot
is excluded unless --include-current is supplied, and counts toward the same cap.

```sh
./bin/faultlens incidents
./bin/faultlens incidents --system-journal --boot-count 7 --json
./bin/faultlens incidents --include-current --boot-count 2
```

## Selection and collection

One scope-specific boot listing is collected and strictly validated. The newest
eligible visible indices select immutable IDs from that snapshot. Each tail is queried
by its selected ID in the same scope. Reboots, changed relative indices or disappearing
history never substitute a different boot. The listing is not repeatedly collected.
Visible indices can be sparse; they do not enumerate every physical reboot.

Maximum native calls: one listing plus seven tail queries. Every call retains the
existing trusted executable, fixed argv, no shell/stdin/pager, two-second deadline and
256 KiB combined output cap. Worst-case subprocess time is approximately 16 seconds
plus bounded cleanup/processing, rather than a guaranteed instantaneous overview.
Collection is sequential, with at most one boot's detailed analysis retained before
reducing it to a summary. There is no polling, background worker or report store.

Each boot requests at most 501 tail records and retains at most 500. Summary data
includes source/parse state, observed counts and caps, first/last references, rule
counts, journal scope and conservative shutdown/root-cause assessments. Full finding
text and raw messages are not copied into the overview. Text output supplies an
exact boot-ID/scope follow-up command for `diagnose`. Monotonic timestamps are
boot-local and are never compared to infer chronology or causality across boots.

## Availability and evidence

Overall state is available if every selected tail has retained records, partial if
only some do, and unavailable if none do. A failed/empty listing or no eligible
previous boots is unavailable, without a current-boot fallback. These states describe
collection, not system health. CLI exit semantics remain consistent: a structured
unavailable report can exit zero; automation must inspect state and completeness.

Counts describe recorded reports, not independent incidents. A shutdown marker
establishes initiation only, and its absence never proves an unexpected shutdown.
Completeness and root cause remain unknown. A cap, rotation, permissions, silent
period or freeze can hide relevant events. More visible boots do not strengthen an
unsupported causal conclusion.

Basic/extended Atop, targeted searches and live/archive pstore remain explicit single-boot diagnose
options; incidents rejects those flags instead of multiplying sensitive collection
across boots. Pstore is never attributed to a selected boot. No service, dependency,
configuration change or network connection is introduced.

Synthetic tests cover selection, caps, sparse indices, immutable IDs, scope consistency,
malformed/failed listings, independent tail failures, privacy and shutdown uncertainty.
The benchmark reviews seven invented 501-record boots. A read-only native smoke
returned one accessible previous boot; explicit system scope correctly remained
unavailable under existing permissions. This is not full-distribution acceptance.
