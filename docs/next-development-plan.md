# Next development proposal

Status: proposed on 2026-11-22 after the owner's request to finish stabilization
and start planning the next work. The four-step 1.1.0 delivery is complete. This
document proposes the next sequence; it does not authorize feature implementation,
a release or a wider host-security product. The [delivery plan](delivery-plan.md)
remains the execution record.

## Goal and order

Help an administrator answer what failed, when it was reported, which concrete
records support that answer and what to inspect next. Prioritize earlier incidents
as well as present symptoms. A boot is an optional evidence filter, not the main
organizing unit. Complete one step and its acceptance before starting the next.

| Order | Proposed work | Administrator outcome | Acceptance |
| --- | --- | --- | --- |
| 1 | Service history for the selected incident period | Investigate a service failure from an earlier period even if the service has recovered or the server restarted | A bounded service query uses the chosen receipt-time range and optional boot filter; current manager state stays separate from historical attempts; original messages and missing/capped coverage remain inspectable |
| 2 | Resource recordings aligned with the incident period | Compare the reported fault with existing resource history instead of relying on current readings or a last-record anchor | Explicitly report which dates, intervals and files were examined; define total read/file/sample limits before implementation; gaps, resets, midnight boundaries and unverified host/boot identity stay explicit |
| 3 | Storage-fault follow-up from original reports | Follow an I/O or filesystem report to the reported device/mount and relevant service evidence | Retain exact messages and times; distinguish present capacity from past I/O failures; explain ambiguous device/mount associations without inferring hardware failure |

Step 1 is the recommended first implementation. The current service reader obtains
current-boot unit logs, while general investigation supports selected periods.
Connecting those capabilities addresses a concrete retrospective gap without
requiring a new service, database, recording policy or external dependency.

Step 2 requires an architecture decision about bounds and file selection before
editing readers. The existing one-file, two-hour replay remains supported until
that decision is reviewed. Do not silently scan all recordings or claim that
matching timestamps prove the recording's host/boot identity.

Step 3 initially uses retained journal and existing local source context. Hardware
health tools, active disk tests, SMART/NVMe collection and new privileges are separate
scope decisions, not implicit prerequisites.

## Shared completion criteria

- Explain concrete observed messages, source/time scope, uncertainty and a useful
  next investigation. Inaccessible evidence remains unassessed, never an all-clear.
- Retain complete administrator evidence without privacy masking; escape hostile
  terminal controls and never turn evidence into executable commands.
- Test synthetic positive, healthy/recovered, ambiguous, inaccessible, empty and
  capped cases, including cross-restart periods and actual frontend navigation.
- Keep local read-only defaults, existing access, bounded/cancellable collection,
  exact dependency locks and all existing resource budgets.
- Work on staging, inspect the final diff and merge only after security, source,
  platform and installed Debian/Ubuntu package checks pass. Publish a new official
  GitHub release only when the owner requests it.

## Optional future scope

Broader security analysis and package/CVE assessment remain possible later roadmap
items. They are outside this proposed fault-investigation sequence. Automatic
repair, blocking, packet capture, remote probes, cloud services and daemons are
not added by these steps.
