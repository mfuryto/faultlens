# Stabilization and product fit

## Current sequence

The [delivery plan](delivery-plan.md), updated 2026-11-22, governs new work in four
steps: general service troubleshooting; processes/storage; practical Network with
possible attack/attempt investigation (DDoS is one example); coherent incident/evidence flow and Signals role.
Step 1 is merged in PR #68. Step 2 adds bounded live process and mount-capacity
investigation; the [source design](architecture/system-process-storage.md) describes
coverage and acceptance. Step 3 adds [practical network investigation](architecture/practical-network-investigation.md);
step 4 adds [coherent inquiry/evidence navigation](architecture/coherent-investigation-flow.md)
and a derived Signals role, gated by the same source/package/resource checks. The original milestones below retain their dated evidence. The service workflow
now has a [shared interpretation/navigation design](architecture/general-service-troubleshooting.md).

## What the application solves

Faultlens provides a local administrator workspace for bounded measurements and
retained evidence. It can identify supported reports and explain their meaning,
source, confidence, limits and follow-up. It does not automatically establish why
an arbitrary server froze or guarantee that an attack did not occur.

| Operator question | Current answer | Remaining gap |
| --- | --- | --- |
| What is happening now? | Prioritized CPU/load/RAM/swap/network readings, bounded process CPU/RSS, mount space/inodes and system-service failure context | Bounded PID/mount coverage; no complete inventory, hardware health or all-unit/user-service inventory |
| What happened around an earlier boot/problem? | Immutable journal boot selection, bounded tail/filtered searches, chronology, Atop replay and optional pstore fragments | Logging may be lost; full shutdown completion and arbitrary root cause remain unverified |
| Was memory/storage/kernel failure reported? | Supported OOM/panic/I/O/filesystem/stall signatures with original references | A signature is not the underlying cause; hardware/vendor evidence and labeled incident validation remain necessary |
| Is network activity suspicious? | Three bounded counter intervals, numeric address/route context, reported socket owner/service associations, peer review and narrow SSH/UFW/historical indicators | No expected-peer baseline, external-reachability probe, effective firewall-policy audit, all-authentication coverage or comprehensive intrusion detection |
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

### Incident period selection

Readable explicit-offset date/time selection and consistent journal-query bounds are
tracked in [the time-window design](architecture/incident-time-window.md). Existing
Unix-microsecond settings remain compatible. This is milestone 2 work; real server
usefulness and cross-server/SSH acceptance remain pending.

### Reproducible contrasting-platform gates

The strict baseline now includes native CLI process checks on Ubuntu 24.04/Python
3.12 and a digest-pinned, non-root/offline/read-only Debian 12/Python 3.11 sequence.
Debian tests the dependency-free CLI before optional frontend installation, the
full suite after offline hash-locked installation, and native contracts again.
See [qualification](architecture/platform-qualification.md). These are automated
qualification candidates, not completed real-server/SSH or production-support gates.

The contrasting-platform gate exposed delayed focus from an inactive pane overriding
a newer tab selection. A workspace focus guard and deterministic regression now keep
the explicit section selected; 30 one-CPU Debian repetitions passed without relaxing
the existing navigation or resource limits.

## Modal rendering stabilization — 2026-11-18

Use opaque modal-screen backgrounds while inspecting details and original evidence.
This avoids alpha blending with the underlying workspace; closing the dialog restores
that workspace, with the same evidence links, retained records and navigation.

Local Python 3.14.4 / Textual 8.2.8 measurements used four alternating pairs of the
existing synthetic `tui-diagnostic` worker with one-CPU affinity and the 128 MiB
address-space profile. Median process CPU was 0.473895 seconds with the former
60-percent background and 0.435166 seconds with the opaque background (about 8 percent
less). These are local comparative measurements, not server qualification or proof
that runner-dependent resource variation is resolved. No benchmark scenario, CPU,
wall-time, memory limit or dependency was changed. Existing navigation/evidence tests
and full platform/resource gates remain required.

## Comparable resource-test runtime — 2026-11-18

The resource gate previously mixed application startup/navigation with repeated source
compilation. The Debian qualification mounts the checkout and interpreter read-only,
and workers prohibit bytecode writes. Unlike an ordinary installed/precompiled runtime,
every fresh worker could compile the same modules again. Profiling the pinned Debian
image observed 397 compiler calls; this avoidable cost reduced margin on slower CI
processors, including the 25-second aggregate benchmark deadline. Physical runner
speed and scheduler noise remain variable; this correction does not claim identical
timings across hosts.

Both resource drivers now prepare private CHECKED_HASH bytecode once for the current
stdlib, checkout and exact reviewed frontend closure. Every measured worker remains a
fresh isolated process and imports source-verified code from that cache. The complete
CLI/TUI scenarios, source data, iteration counts, one-CPU affinity, address-space limits,
CPU below 1 second, wall below 2 seconds and RSS limits are unchanged. Setup time is
reported separately from per-worker startup and remains inside the existing 25/30-second
outer test deadlines. No rerun, skip, calibration or passing-result selection is added.
This explicitly qualifies a prepared runtime, not cold source-to-bytecode compilation
or a cold filesystem cache. Direct `--worker` probes remain usable without preparation
for cold-source investigation; these numbers must not be compared without noting setup.

The cache uses a new owner-only temporary directory, checked source hashes, and
cleanup on normal/error exit. Neither installed packages nor the checkout are written.
Missing/mismatched locked dependencies or compilation errors fail preparation. The
application launch path and server configuration are unchanged. Tests check stale
same-size/same-mtime source rejection, private cache permissions, cleanup and failure
restoration. Both resource gates passed under the original deadlines in the exact
restricted Debian container (10.6 and 9.2 seconds in the initial local run). Real SSH
and second-server operator acceptance remain pending.
