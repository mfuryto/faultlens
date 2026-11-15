# Stabilization and product fit

## What the application solves

Faultlens provides a local administrator workspace for bounded measurements and
retained evidence. It can identify supported reports and explain their meaning,
source, confidence, limits and follow-up. It does not automatically establish why
an arbitrary server froze or guarantee that an attack did not occur.

| Operator question | Current answer | Remaining gap |
| --- | --- | --- |
| What is happening now? | CPU/load/RAM/swap/root-filesystem/network readings and selected service checks | No complete live process attribution, all-filesystem/hardware health or full failed-unit inventory |
| What happened around an earlier boot/problem? | Immutable journal boot selection, bounded tail/filtered searches, chronology, Atop replay and optional pstore fragments | Logging may be lost; full shutdown completion and arbitrary root cause remain unverified |
| Was memory/storage/kernel failure reported? | Supported OOM/panic/I/O/filesystem/stall signatures with original references | A signature is not the underlying cause; hardware/vendor evidence and labeled incident validation remain necessary |
| Is network activity suspicious? | Short counter samples, numeric TCP/UDP sockets, narrow SSH/UFW log signatures and Possible historical indicators | No external-reachability probe, effective firewall-policy audit, socket-owner attribution or comprehensive intrusion detection |
| Can I trust the conclusion? | Explicit bounded evidence, provenance, original records and Confirmed/Possible/Unknown distinctions | Authenticity under root/kernel compromise and empirical detector accuracy are not established |

Important practical gaps:

- Atop host/boot identity is unverified. Matching times or host-name strings alone
  do not prove the recording belongs to the selected boot.
- The replay window is 30 minutes around the last retained journal record. Historical
  traffic comparison requires six contiguous comparable samples. A 600-second recorder
  cannot normally supply six such samples in that window. The current result must
  remain insufficient history; a separately designed, explicitly bounded longer-window
  option is preferable to silently changing server sampling or inventing a baseline.
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

## Next acceptance and priorities

1. Use the corrected workspace on the actual server through SSH; check the known
   recording date and available journal scope, plus ordinary/admin access separately.
2. Review a small labeled set of known positive and normal cases. Record misses and
   false positives before changing thresholds or advertising diagnostic accuracy.
3. Prioritize a bounded longer historical window and stronger recording/boot provenance
   if the real incident workflow requires them. Then consider supported authentication
   formats, live unit failures and process/socket attribution based on actual evidence.
4. Choose support policy, license and exact release artifacts only after acceptance.
   No license or release publication is authorized by this engineering work.

No additional feature is silently claimed as implemented. No daemon, database,
cloud integration, automatic export, server configuration change or blanket package
installation is required by this plan.
