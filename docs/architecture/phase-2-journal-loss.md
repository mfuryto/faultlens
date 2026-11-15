# Phase 2: journal-driver loss observations

Status: implemented narrow journal-driver rules, pre-release. These findings help
explain evidence limitations; they do not reconstruct the missing content or prove
why a host failed. No new collector, dependency, query, privilege or configuration
change is introduced.

## Supported evidence

Both rules require `_TRANSPORT=driver` and the exact structured systemd MESSAGE_ID.
Driver transport is assigned by journald to its internal reports; ordinary application
text or a copied MESSAGE_ID with journal/stdout/syslog/kernel transport does not match.
PID/comm names and natural-language messages are not used as substitutes. A structured
report can match even when MESSAGE is missing or unsupported.

| Rule | Structured event | Confirmed observation |
| --- | --- | --- |
| journal.messages_suppressed | JOURNAL_DROPPED | Journald recorded a rate-limit suppression report |
| journal.kernel_messages_missed | JOURNAL_MISSED | Journald recorded a missed-kernel-message report |

The implementation recognizes protocol identifiers, without copying upstream code.
Raw text, reported counts, unit/process names and affected message contents are not
extracted or echoed. Each finding carries the normalized evidence reference, fixed
reasoning and recommendations. Observation confidence is Confirmed; cause confidence,
root cause and shutdown outcome remain Unknown. Root/kernel compromise can falsify
local evidence and remains outside these checks.

## Scope and limitations

Rules apply to the ordinary selected-boot tail or requested receipt-time window,
under the existing 501-response/500-retained record, 256 KiB and two-second limits.
Reconstruction and timeline include the reported observation at journal receipt time.
That time does not define when loss began or ended. Multiple reports are not counted
as independent incidents, and unrelated temporal gaps are not relabeled as lost logs.

`--search-events` retains its two existing kernel-warning and PID-1 profiles. Neither
collects journal-driver reports, which may have informational priority. Therefore
this feature does not search the complete boot for suppression or loss. Narrow the
ordinary window around known evidence when needed. No match, an empty window or an
uncapped result does not establish complete logging. Other loss mechanisms and
unsupported versions may leave different evidence or none.

Investigate policy and log volume locally before considering changes. Faultlens does
not disable rate limits, enlarge storage, flood the journal or alter permissions.

## Verification

Synthetic tests cover both IDs, spoofed transports, unknown IDs, absent/binary text,
raw-data exclusion, repeated/capped reports, receipt windows and independent filtered
search. A fresh-process benchmark exercises 500 retained mixed driver reports.
CI never induces actual log loss or reads its host journal. Real target-host detection
and log-loss magnitude are not claimed as validated.

Primary references: [systemd message identifiers](https://github.com/systemd/systemd/blob/v253/src/systemd/sd-messages.h),
[journald driver and suppression reporting](https://github.com/systemd/systemd/blob/v253/src/journal/journald-server.c),
[kernel sequence-loss reporting](https://github.com/systemd/systemd/blob/v253/src/journal/journald-kmsg.c).
