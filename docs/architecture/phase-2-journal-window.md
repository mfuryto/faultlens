# Phase 2: bounded historical journal tails

`diagnose --until-us` ends the ordinary journal tail at an explicit receipt-time
boundary instead of the latest available records. This allows a bounded look back
around a reference from targeted search without retrieving an entire boot. It does
not increase the retained-record cap, infer full time coverage or change access.

Use the integer `realtime_us` value from a normalized evidence reference and select
the same boot and journal scope. This example uses invented values; replace them
with references from the intended history:

```sh
./bin/faultlens diagnose --boot-id 0123456789abcdef0123456789abcdef --system-journal --until-us 1767225600123456 --json
```

The option accepts ASCII decimal Unix microseconds, from zero through the existing
journal timestamp maximum (end of year 9999). Negative, fractional, relative, locale-
dependent and nonnumeric values are rejected. Zero is an explicit boundary, not an
unset selector. The flag is valid only for diagnose and can accompany ID or index
selection. Boot-ID/scope validation and no-fallback behavior are unchanged.

## Collection and validation

The fixed runner converts the integer with division/remainder into a journalctl
`--until=@seconds.microseconds` argument, avoiding floating-point rounding, local
timezones, arbitrary date expressions and shell interpretation. It still requests
at most 501 records from the selected immutable boot and retains at most 500. The
existing trusted executable, no-shell/stdin/pager, two-second subprocess deadline
and 256 KiB output limit apply. No collector, package or privilege is added.

Every returned record, including the sentinel before trimming, is checked against
the inclusive receipt-time upper bound and selected boot. Unexpected later/mixed-
boot records reject the whole response. A failed or empty historical query never
retries without the boundary, chooses the latest boot tail or switches journal scope.
An empty window does not prove an absent boot, quiet system or successful shutdown.

## Report semantics

The additive `journal_window` object records tail vs tail_until_realtime mode,
requested until_realtime_us and unknown completeness. Text output shows this metadata.
`last_record`, reconstruction, main findings and source counts describe the returned
historical window, not the latest record of the boot. Atop replay remains centered
on the last returned journal record, not the requested cutoff if there is a quiet
interval before it. Pstore retains its separate unverified boot association.

`--search-events`, if requested, still performs its two whole-selected-boot filtered
candidate queries. It is not silently narrowed by --until-us and can return candidates
after the ordinary-tail boundary. Those results stay in event_search with their own
limits and unknown completeness. No filtered views are merged into continuous coverage.
Root cause, shutdown assessments and overall report exit-code semantics are unchanged.

Receipt timestamps are not necessarily event times. Clock corrections can make a
wall-time selection ambiguous, and equal timestamps need not identify a unique record.
Rotation, permissions, new writes and record/byte/time limits can change later results;
this is not an immutable evidence snapshot or guaranteed cursor pagination. Review
returned references and clock-mapping limitations. Existing bounds still apply even
if a noisy window spans only seconds.

## Verification and remaining scope

Synthetic tests cover exact boundary formatting, zero/maximum/inclusive boundaries,
scope/identity consistency, default behavior, all-record validation including an invalid
sentinel, failed/empty responses without fallback, malformed CLI/API input, unresolved
boots, independent targeted-search scope and Atop's last-returned-record anchor.
The existing system benchmark now combines exact ID and receipt boundary selection
with 500 retained synthetic records. A local read-only smoke accepted the fixed native
time syntax and returned only records at/before a copied accessible reference. No
host log contents or IDs were printed or saved by that check.

Broader time-range UX, explicit pagination, immutable evidence capture and complete
incident reconstruction remain future work. No real reboots, clock changes or
privileged CI tests are used, and phase 2 is not complete.

Primary references: [systemd timestamp syntax](https://github.com/systemd/systemd/blob/v253/man/systemd.time.xml),
[journalctl time filtering](https://www.freedesktop.org/software/systemd/man/253/journalctl.html).
