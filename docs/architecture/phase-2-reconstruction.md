# Phase 2: retained journal chronology

Diagnose now describes the chronology and coverage of its existing retained selected-
boot journal tail. It adds no collection command, privilege, package or live system
change. History listing, source validation, the 501-record response sentinel,
500-retained-record cap and byte/deadline limits remain unchanged. This milestone
is an evidence-window reconstruction, not full incident or boot reconstruction.

## Window and evidence positions

The additive `reconstruction` object reports the first/last retained references,
record count, monotonic span, largest adjacent record interval, equal-timestamp pair
count and finding counts by rule. First/last visible records are not asserted to be
boot boundaries, crash times, incident onset or shutdown completion. A long interval
between records does not prove downtime, a freeze, missing logs or inactivity.
Finding counts describe reports, not distinct incidents. Unsupported-message counts
are explicitly for the collected response, including any omitted sentinel record;
they are not mislabeled as retained-record counts.

Timeline entries preserve their existing rule ID and evidence reference and gain a
finding index, offset from the first visible record, distance to the last visible
record and interval since the preceding finding. All durations use integer
microseconds derived from journal receipt metadata. They are not independent event
measurements or durations of the underlying reported problem. Equal monotonic
finding timestamps retain input order and mark their relative order unresolved;
there is no causal edge, inferred incident grouping or cross-boot comparison.

Empty retained input has an unavailable reconstruction. When boot selection,
collection or parsing fails before reconstruction, the object is null. A readable
window without recognized findings still has an available chronology with zero
finding counts. Existing report exit codes and root-cause/shutdown assessments do
not change. JSON additions are additive; no raw messages, process metadata or
unhashed cursors are copied into summaries. Normalized times and boot references
can still be sensitive and should be reviewed before sharing.

## Clock mapping

Chronology uses boot-local monotonic receipt timestamps, preserving order when the
wall clock regresses. The report exposes adjacent wall-clock regression counts and
the range of `realtime - monotonic` offsets over all retained records. Regressions
are counted only between strictly increasing monotonic timestamps; wall-clock
differences at equal monotonic times are counted separately with unresolved order. A shared
2,000,000-microsecond tolerance is used both here and by the existing Atop pairing
gate. The mapping assessment is `variable` above that range and `within_tolerance`
otherwise. Neither label authenticates clocks, identifies the cause of variation
or guarantees accurate cross-source event timing.

Adjacent offset changes larger than the tolerance are counted with at most 16
before/after reference examples, signed offset deltas and explicit order qualifiers. The total count and an
explicit truncation flag remain visible beyond that limit. Gradual offset drift
can exceed the global tolerance without any single adjacent change doing so; both
measurements are reported separately. Clock corrections, suspend or source semantics
remain alternatives; Faultlens does not diagnose or change clock configuration.
Monotonic spans are not asserted to be elapsed wall time or whole-boot uptime.
Pstore records retain their unverified boot association and are not inserted into
the journal chronology. Atop remains optional and temporal only.

## Validation and remaining work

Synthetic tests cover receipt windows, finding positions, repeated/equal timestamps,
clock regressions, gradual mapping changes, tolerance boundaries shared with Atop,
example truncation, very long silent intervals, record caps, unsupported messages,
empty/failed input, raw-field redaction and unchanged shutdown uncertainty. No real
clock changes, fault injection or diagnostic fixtures are used. All existing
benchmark modes now include reconstruction where applicable. A new clock mode
verifies 500 mixed findings and 499 offset changes with bounded examples.

A local read-only smoke returned a usable current-boot window with mapping within
tolerance and no rule matches. It verifies compatibility, not incident-detection
accuracy or complete journal coverage. Broader evidence selection, target-host
validation, full incident reasoning and shutdown verification remain future phase-2
work. No root cause is inferred by this milestone.

Primary reference: [systemd journal addressing metadata](https://www.freedesktop.org/software/systemd/man/258/systemd.journal-fields.html).
