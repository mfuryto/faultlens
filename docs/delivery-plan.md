# Faultlens delivery plan

Updated 2026-11-22. This is the single forward-work sequence, approved by the owner.
Versions 1.0.0 and 1.0.1 are published in ordinary GitHub Releases. The owner has
used Faultlens on another server and reported resolving the observed service fault.
This is useful operator feedback, not an invented pass for every acceptance case.

## Ordered work

| Order | Work | Status | Operator outcome |
| --- | --- | --- | --- |
| 1 | General service troubleshooting | Completed — PR #68 | Open any listed failed system service, understand the reported failure, read a concrete message and continue to the next evidence |
| 2 | Processes and storage in System | Completed — PR #69 | Find the process or filesystem related to observed resource pressure |
| 3 | Practical Network and possible attack investigation | Completed — PR #70 | Understand connection failures, traffic pressure and evidence of possible current or earlier attacks |
| 4 | Coherent History / Investigate / Evidence flow and Signals role | Completed — PR #71 | Follow one incident across retained sources with clear context and provenance |

All four steps are merged in PRs #68–#71. The owner authorized the combined
1.1.0 release on 2026-11-22 after the earlier merge-only delivery. Release preparation
uses a reviewed staging PR, green source/platform/package/security gates, the exact
verified main commit, qualified final assets and ordinary GitHub Releases.
Whole-host security/CVE auditing remains possible future scope.
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

Implemented bounded live PID/name/CPU/RSS tables and reported system-service
associations, with all retained originals. Mount-specific capacity and inode
measurements extend beyond root; missing, excluded, read-only and capped sources
are distinct. Independent workers preserve source failures, identity checks and
existing resource limits. See the [design and acceptance cases](architecture/system-process-storage.md).
Hardware health and complete process/storage inventory remain outside this step.

Exit evidence: a busy process, independent full filesystem/inodes, healthy host,
container scope and inaccessible source produce useful, distinct answers. Do not
infer historical pressure from a current reading or run a repair/cleanup operation.

## Step 3 — practical Network and possible attack investigation

The owner wants broad practical visibility into possible network attacks and attempts.
DDoS is one prior experience and example, not the organizing architecture or a reason
to restrict the feature set. Start with incident questions and available evidence,
using one shared model: symptom, time/scope, affected service, protocol/endpoints,
reported peers, observations, confidence, benign alternatives and next investigation.
This remains local incident investigation, not a comprehensive security verdict.

1. Establish context: local addresses, routes/link state and permitted socket-to-
   process/service attribution. Separate namespace, interface and IP-family coverage;
   never infer Internet reachability from a local listener alone.
2. Investigate different patterns through the same evidence model: scan-like activity,
   repeated authentication failures, unexpected connections or outbound traffic,
   possible service misuse, connection/listener pressure and traffic/resource floods.
   DDoS belongs to the last group as one example; no single pattern defines the UI.
3. Explain measured packet/byte rates, relevant TCP states, SYN-cookie/retransmission/
   listener-overflow/drop and UDP-error observations where supported. Use explicit
   intervals, multiple comparable samples and qualified history/baselines. A high
   rate, an unfamiliar endpoint or a failed login alone does not establish an attack.
4. Link existing authentication/firewall/application evidence to chosen periods,
   peers and affected services. Describe what was logged: firewall labels do not
   prove final packet verdicts, and an address does not identify a person. Do not
   silently extend narrow SSH/UFW readers into claims of complete attack coverage.
5. Support retrospective checks from existing recordings/logs, with timestamps and
   declared reset/gap/retention coverage. Host counters cannot reconstruct unrecorded
   packets, per-peer UDP traffic or an earlier attack by themselves.
6. Explain benign alternatives: legitimate demand, backups, administration, proxies/
   NAT/load balancers, retransmissions, slow applications and inadequate capacity can
   resemble attack signals. A quiet snapshot cannot rule out earlier/intermittent
   activity. Unknown or inaccessible sources never become an all-clear.
7. Explain visibility limits where relevant, including upstream saturation before
   traffic reaches the host. Suggest reviewing existing edge/provider evidence when
   needed; do not require provider APIs, cloud services or new external collectors.

Show justified observations and possible indicators with original references and
concrete next steps. Avoid blanket attack classifications and attack-specific special
screens. Keep collection extensible through reviewed local sources and explicit
bounds; no automatic packet capture, remote probes, reputation lookup, blocking,
firewall/rate-limit changes or production attack tests.

Synthetic acceptance must cover normal operation, legitimate bursts, scan-like cases,
authentication-failure patterns, unexpected-connection examples, service pressure and
flood-like traffic, plus proxy/NAT ambiguity, missing/reset/wrapped counters, IPv4/IPv6
coverage gaps and absent history. Tests exercise interpretation without generating
real attacks. Resource limits still apply. [Kernel networking semantics](https://docs.kernel.org/networking/ip-sysctl.html)
are a reference, not automatic tuning instructions.

Implementation: the [shared network investigation design](architecture/practical-network-investigation.md)
covers three short counter intervals, numeric link/address/route context, permitted
reported socket owner/service associations, concrete observation cards and original
socket/log/period navigation. Narrow SSH/UFW and qualified Atop evidence remain
explicitly scoped. Peer expectation and application-log review are operator decisions;
there is no automatic unexpected-peer, whole-firewall or all-authentication verdict.
Resource budgets and local read-only defaults remain unchanged. Step 3 merged
without publishing a stable release; existing assets are preserved.

## Step 4 — coherent incident and evidence flow

Make History more event-oriented while keeping boot identity optional where the
query permits. Preserve selected service/time/source context through Investigate
and Evidence, with direct navigation and original references. Clarify the Signals
role and consolidate duplicated information before adding features there. Settings
must explain collection purpose, required access and actual source availability.

Exit evidence: the operator can follow one reported symptom to a time range,
related sources, supported explanation and next step without losing context or
browsing JSON as the primary interface. Cross-boot time uncertainty stays explicit.

Implementation: [coherent investigation flow](architecture/coherent-investigation-flow.md)
adds event-oriented History entries with linked original records, inquiry provenance
on source partitions/current snapshots, explicit service/peer origins and pinned
Evidence selections. Signals reuses the selected inquiry and consolidates verified
shared-reference previews, with source failures and explicit limits. Settings explain
purpose and cached availability without probes. Existing preferences remain compatible.
Automated source/UI/package/resource checks gate merge; new-flow SSH acceptance
remains an operator check. The original step merged without a release; the owner subsequently authorized
1.1.0 publication on 2026-11-22.

## Delivery and future scope

Work on staging, review the final diff and merge to main only after required security,
source/platform and Debian/Ubuntu package checks pass. Keep only main/staging, no
force pushes or branch deletion. Future owner-authorized stable releases use ordinary
GitHub Releases with notes, a qualified `.deb`, corresponding source and checksums.
Whole-host security/CVE analysis remains a possible later roadmap item. It is not
part of the active four-step sequence.
