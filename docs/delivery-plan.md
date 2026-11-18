# Faultlens delivery plan

Status: active operating plan, updated 2026-11-18. The owner prioritizes correcting
the boot-centered investigation workflow before further milestone 3 acceptance.
Earlier operator-usefulness acceptance remains open.
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

Status: implemented and exercised by the owner; usefulness acceptance remains open. The screen/source contract is recorded in
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

Status: problem-centered workflow implementation delivered by explicit owner request, 2026-11-18; operator acceptance remains active. Earlier
boot-first implementation does not satisfy the intended general troubleshooting
entry points. Operator usefulness acceptance remains open. See the
[problem-centered workflow design](architecture/problem-centered-investigation.md).

Deliver three primary entries: **Problems now**, **A selected period**, and
**Before restart**. Boot is an optional filter/source identity, never a prerequisite
for a time-period investigation. The selected period may cross restarts. Current
measurements remain current observations and cannot establish past conditions.
Before-restart selection uses retained previous-boot metadata explicitly, without
claiming that the last record proves a crash or complete shutdown.

Implement and validate the coherent CLI/TUI workflow, original evidence links,
cross-boot bounds/coverage and saved-preference migration in one staging PR.
Keep the existing single-boot diagnostic reader as a technical compatibility API;
it is not the primary user journey. Missing logs must remain an unanswered question,
and independent source results must remain inspectable. No new external service,
dependency, automatic report exposure or server configuration change is added.

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

Status: automated qualification available; operator acceptance waits for the active
milestone 2 workflow correction. Initial candidates are Debian 12 /
Python 3.11 and Ubuntu 24.04 / Python 3.12 on x86-64; see
[qualification scope and evidence](architecture/platform-qualification.md). Neither
is claimed production-supported before the actual server/SSH gates pass.

Owner-server evidence is now recorded in the [server acceptance record](acceptance/server-qualification.md):
the owner reported a passing combined server test and confirmed exclusive SSH use.
Exact target versions, detailed interaction/usefulness approval, real workload impact
and a materially different second server remain open. SSH usage alone is not approval
of all interaction or incident workflows.

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

### 4 — Installable Debian package

Status: owner-approved delivery scope, queued after stabilization acceptance. Deliver
one downloadable `.deb` package, not an APT repository or an implicit public release.
Installing with `apt install ./faultlens_<version>_all.deb` must resolve required
runtime dependencies from the target's existing configured package sources. Running
`faultlens` must open the primary terminal workspace without a manually created
virtual environment; `faultlens tui` remains a compatible alias. Explicit CLI
commands remain available.

Define and test the Python/Textual dependency strategy before implementation. Preserve
the reviewed dependency closure: do not assume the supported distributions ship the
required Textual version. If a private packaged runtime is necessary, document its
layout, licensing, upgrade/security maintenance and reproducible offline build inputs;
never run pip or download dependencies from package maintainer scripts or app startup.
Use Debian dependency metadata for required distribution packages. Do not declare a
runtime package dependency that the qualification targets cannot actually satisfy.

Keep recording/replay tools such as Atop optional, outside `Depends` and automatic
`Recommends`, because their distribution packages may enable services. Explain which
features need them. Installation must not configure recording, alter journal/access
policy, start a Faultlens daemon or modify the server beyond the package-managed
application/runtime files and metadata. Diagnostics still use the caller's privileges.

Exit evidence:
- Build a versioned `.deb` reproducibly with recorded source/dependency provenance.
- Validate package metadata, GPL notices and third-party license inclusion.
- Test clean install with dependency resolution, upgrade and removal in isolated
  supported Debian/Ubuntu targets, including offline failure and unavailable dependency
  cases. No maintainer-script network bootstrap is allowed.
- Launch CLI and TUI as an ordinary user over SSH without checkout paths or `.venv`.
- Confirm optional tools remain optional, no service/access/recorder changes occur,
  and user preferences/evidence are preserved across upgrades and removal.
- Rerun source security, resource and application checks against installed files;
  do not publish a release or claim distribution support from a package build alone.

## Scope exclusions

Owner-requested System context, 2026-11-18: add a bounded local login-session
snapshot with reported username, terminal, login time and source. Use a fixed
read-only local logind queries, with `who --users` as a fallback, in C locale/UTC,
without DNS lookup, arbitrary files or privilege changes. Existing logind is optional
and is never installed/started. Retain reported fields and originals, distinguish
empty/unavailable/unsupported output, and do not claim complete session coverage
or verified authentication. This is administrative fault-investigation context,
not a new security-audit milestone.

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

Available qualification: milestone 3 makes native process checks and the full regression
suite reproducible on the initial Debian/Ubuntu qualification candidates. The strict
CI profile retains read-only tokens and action/image pins. Missing optional tools,
missing system journal and frontend-absent/reviewed setups are explicit test cases.

Current acceptance task: exercise Problems now, a selected period and Before restart
on the operator server and a
materially different server over SSH; record OS/Python/tool versions, access scope,
usefulness, terminal behavior and workload impact. Those gates remain pending.
Use the [single follow-up session and gate table](acceptance/server-qualification.md#one-concrete-follow-up-session)
to update the received results instead of starting unrelated implementation work.
No milestone or production-support claim is closed by container/CI checks alone.

Bounded acceptance aid, 2026-11-18: provide an explicitly synthetic investigation
walkthrough for a reported OOM kill, readable unmatched records and unavailable logs.
This addresses the lack of usable incident messages in the owner's reported run.
Use the actual interpretation and Textual navigation with injected in-memory sources;
never query native sources, load/save preferences or create host faults. Keep the
demo outside normal application commands. It assists explanation/navigation review,
but does not close real incident, SSH or second-server acceptance gates.

Bounded M3 acceptance aid, 2026-11-18: extend the server checker to exercise all three
primary investigation modes in visible/system scopes with no optional boot filter,
and check the System session source. Keep query availability separate from retained
evidence, including empty and capped queries. The automatic recent-period probe is
not owner-selected incident acceptance. Existing manual SSH and second-server gates
remain open; no new product feature or dependency is introduced.

Bounded M3 stabilization task, 2026-11-18: profile the modal evidence-navigation
resource path after runner-dependent CPU failures. Retain only measured improvements,
keep original evidence/navigation and all resource limits intact, and record remaining
qualification variation separately from operator acceptance.

Owner-requested M3 startup stabilization, 2026-11-18: make no-argument invocation
select the primary terminal workspace consistently, retaining explicit CLI commands
and the `tui` alias. Noninteractive no-argument startup must explain the terminal
requirement without silently collecting a status snapshot. Verify dispatch, missing
terminal behavior and CLI independence; source checkout still uses the reviewed
virtual environment until the queued package milestone supplies its runtime.
