# Stabilization and product fit

## What the application solves

Faultlens provides a local administrator workspace for bounded measurements and
retained evidence. It can identify supported reports and explain their meaning,
source, confidence, limits and follow-up. It does not automatically establish why
an arbitrary server froze or guarantee that an attack did not occur.

| Operator question | Current answer | Remaining gap |
| --- | --- | --- |
| What is happening now? | Prioritized CPU/load/RAM/swap/root-filesystem/network readings and bounded system-service failure context | No complete live process attribution, all-filesystem/hardware health or all-unit/user-service inventory |
| What happened around an earlier boot/problem? | Immutable journal boot selection, bounded tail/filtered searches, chronology, Atop replay and optional pstore fragments | Logging may be lost; full shutdown completion and arbitrary root cause remain unverified |
| Was memory/storage/kernel failure reported? | Supported OOM/panic/I/O/filesystem/stall signatures with original references | A signature is not the underlying cause; hardware/vendor evidence and labeled incident validation remain necessary |
| Is network activity suspicious? | Short counter samples, numeric TCP/UDP sockets, narrow SSH/UFW log signatures and Possible historical indicators | No external-reachability probe, effective firewall-policy audit, socket-owner attribution or comprehensive intrusion detection |
| Can I trust the conclusion? | Explicit bounded evidence, provenance, original records and Confirmed/Possible/Unknown distinctions | Authenticity under root/kernel compromise and empirical detector accuracy are not established |

Important practical gaps:

- Atop host/boot identity is unverified. Matching times or host-name strings alone
  do not prove the recording belongs to the selected boot.
- The replay window is two hours around the last retained journal record, within unchanged capture limits and one recording file. Historical
  traffic comparison requires six contiguous comparable samples. A 600-second recorder
  can now supply six such samples when retained data permits. Short, reset, gapped
  or midnight-limited windows still remain insufficient history; no baseline is invented.
- SSH classification is narrow password/invalid-user evidence, not all key/PAM/MFA
  authentication. Firewall classification recognizes selected UFW-labelled kernel
  records, not an arbitrary active ruleset. IPv6 socket/interface support does not
  imply complete IPv6 protocol-counter analysis.
- Pstore fragments have no verified selected-boot attribution; missing/empty archives
  and unanalyzed binary content do not exclude a crash.
- Synthetic tests exercise known behavior and negative cases, not population-level
  false-positive rates or detection guarantees. Thresholds remain heuristics.

## Corrected interface and acceptance scope

The earlier curses/object-browser frontend did not meet the concrete UserDock
interaction requirement. Earlier completion claims describe that implementation and
are superseded by the Textual tab/table/dialog acceptance review. The new workspace
uses UserDock's navigation model, while retaining Faultlens's read-only source policy.
No UserDock account-management operations or project source are incorporated.

Stabilization checks cover all eight sections, typed settings, actual dialog focus,
arrow navigation, compact SSH layouts, evidence literals, cache/source scope, bounded
collection/cancellation, normal/interrupt terminal restoration and missing dependencies.
The optional frontend adds a reviewed, hash-pinned dependency closure; CLI imports
remain dependency-free. CLI memory regression stays below 50 MiB; Textual workspace
regression is below 80 MiB, with CPU below one second and fresh synthetic wall time
below two seconds. These are measured regression bounds, not promised total VM RAM.

Compatibility includes the development Python 3.14 environment and an official
Debian/Python 3.11 container, tested with read-only source, offline wheel installation,
no network during tests, no capabilities and CPU/memory/process limits. CI additionally
runs on Ubuntu 24.04. Containers share a host kernel; actual target-server/SSH and
small-VPS workload acceptance remain open. Dependency vulnerability scans are dated
checks, not a guarantee against unknown flaws.

## Completed security-workspace stabilization

A live Security report with zero findings previously rendered an empty table. The
workspace now keeps coverage, readable counter counts, socket state, Unknown attack
assessment and a separate selected-boot SSH/firewall navigation row visible. It never
substitutes cached historical diagnosis findings for a live report. Loading, cancelled
and failed collections have explicit states; original unclassified evidence remains
available when a source's finding table is empty.

Immediate tab navigation waits for first-frame initialization before startup collection.
Synthetic normal/positive/missing/partial/source-error cases and actual compact UI
navigation verify the behavior. A native read-only development-host sample with zero
findings rendered five overview rows and retained Unknown. This does not establish
actual target-server acceptance or detector calibration; those gates remain open below.

## Forward delivery sequence

The [delivery plan](delivery-plan.md) is the single forward-work sequence from
2026-11-16. It replaces the former priority list here. This file records actual
capabilities and known gaps; it is not a second roadmap or evidence of operator
acceptance. The new milestones prioritize useful current-server decisions, incident
workflows and cross-server acceptance. General package/CVE and host-security auditing
are outside this plan; network/authentication/firewall observations serve incident
investigation where relevant.

### Current overview delivery

Milestone 1 implements shared System/Health/Network decision views and a bounded
read-only failed-service source. Automated verification and synthetic previews are
recorded in [the milestone design](architecture/milestone-1-current-overview.md).
Operator usefulness and target-server/SSH acceptance remain pending; this is not a
claim that stabilization or the milestone's acceptance is complete.
