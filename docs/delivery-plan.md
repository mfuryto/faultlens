# Faultlens delivery plan

Updated 2026-11-22. This is the single forward-work sequence, approved by the owner.
Versions 1.0.0 and 1.0.1 are published in ordinary GitHub Releases. The owner has
used Faultlens on another server and reported resolving the observed service fault.
This is useful operator feedback, not an invented pass for every acceptance case.

## Ordered work

| Order | Work | Status | Operator outcome |
| --- | --- | --- | --- |
| 1 | General service troubleshooting | Implemented in this change; merge requires green checks | Open any listed failed system service, understand the reported failure, read a concrete message and continue to the next evidence |
| 2 | Processes and storage in System | Queued | Find the process or filesystem related to observed resource pressure |
| 3 | Practical Network investigation, including possible attacks and DDoS | Queued, explicitly prioritized by owner | Understand connection failures, traffic pressure and evidence of possible current or earlier attacks |
| 4 | Coherent History / Investigate / Evidence flow and Signals role | Queued | Follow one incident across retained sources with clear context and provenance |

The implementation in this change completes step 1 once its required checks and
reviewed merge pass. Step 2 is next; Network/DDoS remains explicitly queued as step 3.
Finish and validate one coherent step before starting another. Subtasks belong to
these four steps; do not turn each patch into a new phase or expand scope silently.
The [earlier plan](delivery-plan-history.md) preserves the decisions and evidence
behind the original milestones; it is not a second active roadmap.

## Shared product contract

Every warning must lead to concrete retained data, a supported explanation and a
proportionate next investigation. Show source scope, timestamps, availability and
unknowns. Separate manager state, reported errors, possible explanations and an
unverified underlying cause. Unavailable logs never become an all-clear.

Retained administrator evidence remains fully accessible. Names, addresses, ports,
process identities and original messages are not privacy-masked. Source-controlled
text never becomes executable actions. Keep local read-only defaults, existing
access, bounded/cancellable collection and no automatic external report exposure.
No new daemon, database, cloud service, heavyweight dependency or recording policy
is required by these steps.

## Step 1 — general service troubleshooting

The 1.0.1 reader already opens any listed failed system service. Complete its general
workflow rather than building a separate view for each named product:

- Explain supported systemd results: unsuccessful exit, signal/core-dump, timeout,
  watchdog, OOM kill, start limit, resource/protocol/condition and unit-load errors.
  Unknown results retain their actual values and do not acquire a guessed cause.
- Prioritize concrete explained and error/warning messages, retaining informational
  context and every original record. A user can open an individual message, its
  explanation, surrounding logs, exact fields and a bounded investigation period.
- Keep current state and older log attempts separate. Where supported invocation
  metadata is retained, describe same/different/unverified identity without treating
  it as proof of authenticity or causality.
- Common message rules apply across service names. Existing AppArmor rules are
  optional specific interpretations, never the foundation of service navigation.
- All source failures remain independent. Empty, unavailable, unsupported and capped
  history have different meanings. No restart, reset, repair or configuration write.

Exit evidence: synthetic web/mail/database/worker/template-service examples cover
normal, known failure, unknown message, historical/recovered, missing and capped
sources. Actual Textual tests cover row/message/context/period navigation, keyboard,
resize, cancellation and original fields. CLI, installed packages, existing resource
budgets, repository policy and CodeQL pass. Review staging and merge only on green CI.
The current task authorizes implementation and merge; a new stable release is a
separate owner decision. Preserve existing release tags/assets.

## Step 2 — processes and storage

Add bounded live process CPU/memory attribution and useful filesystem/inode coverage
beyond the root mount. Relate pressure to observed services where evidence permits.
Explain filesystem scope, sampling and process lifetime races. Read-only hardware
health may be considered only with a concrete source and demonstrated need.

Exit evidence: a busy process, independent full filesystem/inodes, healthy host,
container scope and inaccessible source produce useful, distinct answers. Do not
infer historical pressure from a current reading or run a repair/cleanup operation.

## Step 3 — practical Network and possible attack/DDoS evidence

The owner has experienced DDoS and wants practical evidence of attacks or attempts.
Treat this as incident investigation with justified indicators, not a safety verdict
or comprehensive host-security audit.

1. Establish context: local addresses, routes/link state and permitted socket-to-
   process/service attribution. Separate current namespace, interface and IP-family
   coverage; never infer Internet reachability from a local listener alone.
2. Explain traffic pressure with measured packet/byte rates, relevant TCP states,
   SYN-cookie/retransmission/listener-overflow/drop and UDP-error observations where
   supported. Use explicit intervals, multiple comparable samples and qualified
   history/baselines. A high rate alone does not establish an attack.
3. Link existing authentication/firewall/application observations to chosen periods,
   peers and affected services. Describe what was actually logged; a firewall label
   does not prove the final packet verdict, and an address does not identify a person.
4. Support retrospective checks from existing recordings/logs, with timestamps,
   counter-reset/gap handling and declared coverage. Host counters cannot reconstruct
   unrecorded packets, per-peer UDP traffic or an earlier attack by themselves.
5. Explain benign alternatives: legitimate demand, backups, slow applications,
   proxies/NAT/load balancers, retransmissions and inadequate capacity can resemble
   attack signals. A quiet snapshot cannot rule out an earlier or intermittent attack.
6. Explain upstream limits: a saturated provider link can prevent evidence reaching
   the host. Suggest reviewing existing provider/edge evidence when relevant; no
   provider API, cloud service, automatic capture or remote probing is introduced.

Use evidence-backed labels such as reported load and possible attack indicator,
with a concrete next step and unknown cause. No automatic firewall rules, blocking,
rate-limit changes, packet floods, production attack tests or service changes.
Test with synthetic normal/legitimate-burst/SYN-pressure/UDP-error/scan-like cases,
NAT/proxy ambiguity, reset/wrap/missing counters, IPv4/IPv6 gaps and absent history.
Resource limits still apply. [Kernel networking semantics](https://docs.kernel.org/networking/ip-sysctl.html)
are a source reference, not a list of tuning values to apply automatically.

## Step 4 — coherent incident and evidence flow

Make History more event-oriented while keeping boot identity optional where the
query permits. Preserve selected service/time/source context through Investigate
and Evidence, with direct navigation and original references. Clarify the Signals
role and consolidate duplicated information before adding features there. Settings
must explain collection purpose, required access and actual source availability.

Exit evidence: the operator can follow one reported symptom to a time range,
related sources, supported explanation and next step without losing context or
browsing JSON as the primary interface. Cross-boot time uncertainty stays explicit.

## Delivery and future scope

Work on staging, review the final diff and merge to main only after required security,
source/platform and Debian/Ubuntu package checks pass. Keep only main/staging, no
force pushes or branch deletion. Future owner-authorized stable releases use ordinary
GitHub Releases with notes, a qualified `.deb`, corresponding source and checksums.
Whole-host security/CVE analysis remains a possible later roadmap item. It is not
part of the active four-step sequence.
