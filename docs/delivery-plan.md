# Faultlens delivery plan

Status: active operating plan, 2026-11-16. Milestone 1 is in progress; no milestone
is accepted as complete.
This is the single forward-work sequence. It supersedes the priority list in
[stabilization.md](stabilization.md); that document remains the current capability/gap inventory.
The original specification remains the product goal, not a record of delivered features.
Earlier technical phase completion and green CI do not establish operator acceptance.

## Product outcome

An administrator must be able to answer:

1. What deserves attention on this server now, and why?
2. What evidence exists for an earlier failure or suspicious event?
3. What should I investigate or change next, with which limitations?

Scope clarification: Faultlens investigates faults, hangs, outages and service/resource
problems. Authentication, firewall and network observations are supporting incident
evidence when relevant, not a promise of comprehensive system-security assessment.

A table of collected fields does not satisfy these outcomes. The implementation has
useful bounded readers and tests, but its current presentation does not consistently
turn those sources into useful administrative decisions. Fix that product gap before
adding unrelated features, polishing repository presentation or declaring stabilization.

## Mandatory contract for every section

Each primary screen must show, without opening raw JSON:

- A direct answer to the section's operator question, or exactly what prevents an answer.
- Prioritized items needing attention, with readable values, units and sample/boot scope.
- Why each item matters, and a proportionate next step or an explicit "no action indicated".
- Which relevant sources were checked, unavailable, not requested, unsupported or stale.
- A drill-down to source timestamps, thresholds, confidence and unchanged original evidence.

Collection availability, severity and confidence are separate concepts. A readable
counter is not a healthy server; a missing optional executable is not a critical
server fault. "Not explicitly configured; effective default not verified" differs
from permission denial, malformed data, unsupported input and an inactive service.
Unknown/unavailable values must have visible explanations, never empty cells or
invented default/zero values. If a distinction cannot be established, say so.

Summaries prioritize and group information; all retained administrator data remains
reachable, including virtual/idle interfaces, user names, peers, ports and originals.
There is no privacy masking or automatic evidence export. Summary totals refer to
observations/reports, not automatically distinct incidents, attacks or missing records.

## Section purpose and acceptance contract

| Section | Operator question | Required useful primary view | Details and boundaries |
| --- | --- | --- | --- |
| System | What resources or services need attention now? | Resource pressure/capacity and relevant service state, ranked with sampling context | Separate CPU/load, available memory/cache, swap and filesystem capacity; no unsupported process attribution or whole-host verdict |
| Health | Is the server showing a problem, and could I investigate an incident? | Separate current operational issues from diagnostic readiness: services, usable journal history, existing recordings and retention evidence | Tool inventory and unspecified settings are secondary. Explain the impact of each gap; service active/directory present does not prove recording works |
| Network | Which traffic or network symptoms should I investigate? | Activity, errors/drops and relevant socket/listener observations; show interface scope and interval | Group idle/virtual interfaces with an explicit count and access to all. Do not guess a primary uplink from its name or claim Internet exposure from a binding |
| Security | Could authentication, firewall or network events help explain this incident? | Relevant source-scoped observations, time windows, affected peers/services and plausible benign alternatives | Keep this an incident-evidence view, not a general security audit. Review the section label in milestone 2 so it does not promise broader coverage. Package/CVE auditing is out of scope |
| History | Which boot or period is relevant to my incident, and is there evidence? | Human-readable visible time ranges, last recorded events, supported warning/failure summaries and coverage gaps | Boot IDs move to details. First/last retained entries are not exact power-on/crash times; counts are reports, not incident counts. Selecting a row opens the corresponding investigation |
| Diagnostics | What can explain this reported problem? | A coherent selected-boot/time investigation linking journal, recordings and crash evidence where justified | Separate observation, possible explanation and unknown cause. Show orderly-shutdown reports when supported, but missing shutdown records alone cannot prove a crash |
| Evidence | What exactly supports this interpretation? | Direct source references from findings with readable context and complete retained originals | Raw object browsing is a secondary inspection tool; originals never turn themselves into executable actions |
| Settings | What will be collected and what do these choices change? | Purpose, collection cost, access requirements and scope of each option, plus save/load status | Preserve per-user settings, validate/migrate schema changes explicitly, and never silently reset preferences or change server configuration |

### Concrete interpretation examples

These examples describe desired wording/behavior, not findings on the operator's host:

- Health: "No explicit journal size setting was found; the effective default was not
  verified. No configuration change is indicated by that fact alone." Place this in
  readiness details, rather than beside critical operational failures as an empty value.
- Health: "The service manager reports degraded state. These units were observed as
  failed; inspect their logs." Collect a bounded failed-unit list if needed; do not
  claim that this detail already exists in the current implementation.
- Network: "These interfaces carried traffic during the sample; these counters grew.
  Other interfaces are available under All interfaces." Explain what errors/drops may
  affect and what to inspect; do not label a rate suspicious without a justified rule.
- Security: "This supported authentication pattern was observed for this peer and
  interval; these references support it. Automation/proxies can resemble guessing."
  Inaccessible logs produce a coverage gap, not zero attacks.
- History: "These reports make this boot worth reviewing. Evidence ends at the last
  visible timestamp; later conditions are unknown." Link directly to that boot/time.

## Ordered milestones

Only one milestone is active. Complete its coherent operator workflow before starting
the next. Technical subtasks stay under that milestone, not a new direction or a
separate 'phase complete' claim for every small patch.

### 1 — Useful current-server overview

Status: in progress. The screen/source contract is recorded in
[the milestone 1 design](architecture/milestone-1-current-overview.md).

Deliver System, Health and Network using the contract above. Before coding, record
example primary screens for normal, attention-needed and unavailable cases, the
sources each interpretation requires, and the missing-source list. That design is a
bounded task inside this milestone, not another open-ended roadmap exercise.

Implement grouped, prioritized summaries with meaningful values and next steps. Keep
raw configuration/tool lists and all interfaces accessible as details. Add only the
minimum read-only evidence needed for these questions, such as bounded failed-unit/process
context or verified interface context; document source scope and limits before adding it.
Do not infer interface roles, effective defaults or process causes from unavailable data.

Exit evidence:
- CLI and actual TUI demonstrate the three scenarios for all three sections.
- Existing unknown/default/access cases have distinguishable text and no blank values.
- A many-interface/container example remains useful without hiding retained data.
- Show the before/after result and obtain operator feedback on actual usefulness;
  record automated verification separately from operator acceptance.

### 2 — Useful incident investigations

Status: queued behind milestone 1.

Deliver Security, History, Diagnostics and their Evidence links as end-to-end workflows:
select a problem period, see relevant observations, inspect support, understand missing
evidence and choose the next investigation. Present related sources together with
explicit time/boot identity, rather than making the operator interpret disconnected
counters or hunt for the useful tab. Preserve current/historical boundaries. Security
observations belong to the fault investigation; temporal coincidence or suspicious
activity alone does not establish the cause of an outage.

Address the known 30-minute Atop replay limitation for ten-minute recordings with an
explicitly bounded longer-window design. Test six comparable samples, window bounds,
midnight/recording boundaries, resets, gaps and clock changes. Do not change the server's
sampling configuration. Host/boot attribution stays unverified unless stronger evidence
actually establishes it; temporal overlap is not causality.

Exit evidence:
- An OOM/service-failure example and a normal/no-supported-match case are understandable.
- Authentication/firewall examples show why they merit attention, source scope and
  plausible alternatives; missing logs never become an all-clear.
- The forced-reboot investigation explains the last visible evidence and what cannot
  be reconstructed. Shutdown reporting is distinguished from verified shutdown completion.
- Original references remain intact; repeated messages are not called separate attacks.
- Saved boot/date/window settings remain valid or have an explicit tested migration.

### 3 — Cross-server acceptance and stabilization

Status: queued; regression coverage also runs within every earlier milestone.

Select and record exact supported Debian/Ubuntu releases before making support claims.
Exercise contrasting configurations: small VPS, container/many virtual interfaces,
ordinary user and existing administrator access, missing tools/systemd/history,
implicit configuration defaults, healthy and failed services, short/missing recordings,
normal/positive/ambiguous incident-related authentication and firewall observations.

Use bounded synthetic tests for repeatability and negative cases. Also run the useful
workflows over real SSH on the operator's server and at least one materially different
target server; do not claim broad acceptance from one host, Pilot or containers alone.
A lack of target access leaves operator acceptance pending, rather than complete.

Exit evidence:
- The operator can explain what each primary section tells them and the next step.
- CLI/TUI source meaning agrees; terminal resize/cancellation/preferences still work.
- Existing security checks, evidence safety, resource budgets and relevant regressions pass.
- Versioned acceptance results list tested environments, limitations and unresolved bugs.
- The milestone ends in an accepted pre-release, not an automatically published release.

## Scope exclusions

General host-security auditing, installed-package/CVE scanning, patch management,
compliance auditing and comprehensive intrusion detection are outside this delivery
plan. No advisory feed, vulnerability inventory or automatic package update is added.
General host-security assessment and package/CVE analysis are recorded as possible
future roadmap extensions. They require a separate scope decision after the fault-
investigation milestones; they are not queued stabilization work.

Retain useful authentication/firewall/network evidence for fault investigations.
Present its relevance and uncertainty rather than treating a security event as proof
of an incident's cause. Existing repository/source dependency security checks remain
part of safe development, separate from auditing the operator's server.

## Execution and reporting rules

- This plan is the forward-work authority. Update milestone status and acceptance
  evidence here; use stabilization.md for the capability/gap inventory.
- Default to one coherent milestone PR. If technical size requires sub-PRs, define them
  upfront within the same milestone and keep its operator-facing completion gate open.
- Start each work turn by naming the active milestone, deliverable and exit criteria.
- Report what now helps the operator, how it was checked, and what remains unaccepted.
- Track implementation, automated checks and operator acceptance separately. Green CI
  permits an authorized merge; it does not by itself complete a product milestone.
- Work on staging, require green security checks before merging to main, preserve both
  branches, and never weaken required checks or publish a release implicitly.
- No unrelated feature, threshold change, repository polish or new dependency is slipped
  into a milestone. Record a justified scope change first; new owner instructions may
  explicitly change priority. Urgent security defects get a documented exception.
- Keep code/docs/comments/commits/PRs in English and communication with the owner in Norwegian.

Next implementation task: milestone 1, beginning with concrete System/Health/Network
normal/attention/unavailable screen contracts and the minimal source-gap review.
