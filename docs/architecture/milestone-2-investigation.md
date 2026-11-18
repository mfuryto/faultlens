# Milestone 2 — evidence-led fault investigation

The earlier boot-first entry described below is superseded by the owner-approved
[problem-centered workflow](problem-centered-investigation.md), 2026-11-18. History
is optional; Problems now, A selected period and Before restart are primary entries.
This document retains the earlier interpretation/evidence design as background.

Design before implementation, 2026-11-16. The owner requests a coherent workflow
that explains actual fault evidence, rather than reporting only source availability.
Milestone 1 was exercised by the owner; further usefulness acceptance remains open.

## Screen contract

History shows retained UTC ranges and named report examples, not primary boot IDs.
Selecting a boot opens Diagnostics with its immutable identity. Diagnostics starts
with what was reported, receipt time, exact retained message excerpt, implication,
next investigation and gaps. Evidence opens those same original records as readable
text; raw JSON remains secondary. Authentication/firewall counters remain supporting
context, never an inferred outage cause. No general security/CVE auditing is added.

Normal/no-match: say that no supported pattern matched the checked sources, show the
last retained message and time, and guide broader event search, incident boundaries
and optional recording/crash evidence. Never invent a fault to populate a screen.
Positive: an OOM kill shows the actual killed PID/process message; a failed start
shows its original unit report. Their underlying cause and whole-host impact remain
unknown. Shutdown initiation is not completed shutdown. A forced-reboot case shows
where evidence ends and explicitly cannot distinguish a freeze from lost logging.
Unavailable: explain selected scope and actionable access/source checks without
claiming permission denial unless established or substituting zero events.

## Bounds and preservation

No new external collector is introduced. Source references resolve only inside their
own retained report. Primary examples are bounded to six distinct source/rule groups;
History retains three bounded 512-character excerpts per boot, with explicit excerpt
labels. All existing diagnostic originals remain reachable. Untrusted text is escaped
at rendering, never interpreted as markup or executed. Readable CLI diagnostics retain
original evidence in memory so actual messages can be shown; JSON's explicit
--show-evidence option remains unchanged.

Atop replay expands from 30 minutes to two hours centered on the last retained
journal record, allowing six ten-minute samples before that anchor when recordings
contain them. Existing byte/sample/process/deadline limits remain unchanged. Replay
uses one explicit date/file, does not cross to adjacent files automatically and may
therefore be partial at midnight. RESET/gaps/clock ambiguity and host/boot uncertainty
remain explicit. Saved settings schema is unchanged.

## Acceptance

Test OOM, failed start, shutdown-only, no-match, inaccessible and forced-reboot-like
last-record cases; resolve original messages and timestamps without guessed links.
Exercise actual Textual navigation from History to Diagnostics to readable records,
including compact terminals. Test two-hour command bound, comparable six-sample
coverage, recording boundaries, resets and existing clock protections. Run existing
security, resource and cross-Python regressions. Operator incident usefulness and real
SSH acceptance remain separate from a green merge.

## Rendered workflow examples

These are actual Textual renders of invented records, not production incidents:
[History](../previews/workspace-history.svg),
[Diagnostics](../previews/workspace-diagnostics.svg),
[readable original messages](../previews/workspace-records.svg).
The selected-row reader shows the message, meaning and first follow-up directly;
Enter opens complete interpretation and Records opens the retained originals.

The former Security tab is labeled Signals. Its live counter and explicit historical
links remain supporting incident evidence; the CLI command is unchanged. No broad
host-security or package/CVE assessment is implied.

## Verification and remaining acceptance

- Python 3.14.4: all 515 tests passed. Python 3.11: the same 515 tests passed in
  an offline read-only container with hash-locked frontend dependencies.
- Scenarios cover actual OOM/failed-start/shutdown messages, unknown warnings,
  no-match/silence, unavailable sources, unresolved references, literal hostile text,
  selected-row evidence, History-to-Diagnostics navigation and bounded record paging.
- Two-hour replay tests retain six ten-minute samples, reject over-limit requests,
  exclude out-of-window samples and preserve one-file midnight limitations. Existing
  RESET/gap/clock-ambiguity protections remain covered.
- Repository policy and Gitleaks working-tree/reachable-history scans passed.

Operator acceptance remains pending. On the target server, open History, select the
relevant boot, choose Investigate this boot, and read the selected message/meaning/next
step. Open Records and compare the exact original. For no-match or unavailable data,
check whether the explanation makes the missing scope and next investigation clear.
Use existing authorized system-journal access when server-wide evidence is required;
Faultlens does not change groups, permissions, logging or recorder configuration.
Do not manufacture a crash or service failure for acceptance testing.

All 28 benchmark modes passed ten iterations and all 63 constrained-process runs
passed the unchanged budgets. The diagnostic benchmark opens a real finding and
readable linked record dialog. See [resource measurements](../benchmarks.md#evidence-led-investigation-workflow--2026-11-16).

The next delivery aligns all requested journal searches with the selected incident
period and adds explicit-offset date/time input; see [time selection](incident-time-window.md).
This supersedes the earlier whole-boot-only event-search scope when bounds are set.
