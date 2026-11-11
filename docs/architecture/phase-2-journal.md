# Phase 2, milestone 1: bounded journal history and event analysis

Status: implemented initial journal-only milestone, pre-release. Full incident
reconstruction, atop integration, resource correlation, retention setup and TUI
remain future work. No license, daemon, database or dependency is introduced.

## Commands

```sh
./bin/faultlens history
./bin/faultlens history --json
./bin/faultlens diagnose --previous-boot
./bin/faultlens diagnose --boot -2 --json
./bin/faultlens diagnose --boot 0
```

History lists up to 128 visible journal boot indices and validated boot IDs. Locale-
dependent date text is not interpreted or echoed. Indices refer to the history
visible to the current user, not necessarily every boot that physically occurred.
Diagnose defaults to index -1; index 0 is an explicit request to inspect the current
visible boot. Supported selection range is -128 through 0. Boot-selection flags are
rejected on unrelated commands. Calendar filtering (`history --last 7d`) and the
multi-boot `incidents` overview are not implemented yet.

Resolve the relative index to an immutable boot ID first, then query that ID. A
reboot between calls cannot silently change the chosen scope. Missing previous
history never falls back to current-boot data. Both calls use the trusted read-only
command runner, ordinary user permissions, two-second deadlines and a combined
stdout/stderr cap of 256 KiB. A collection failure produces unavailable analysis;
it does not invite automatic elevation or a configuration change.

Journal query: `journalctl --boot=<validated-id> --lines=501 --output=json --no-pager
--quiet --output-fields=MESSAGE,MESSAGE_ID,_TRANSPORT,_PID,_COMM`. Journalctl always
includes the boot identity, cursor and realtime/monotonic addressing fields for JSON
output. The output-fields interface exists in the systemd versions in the initial
modern Debian/Ubuntu targets; incompatible versions fail as unavailable.

## Module boundaries and provenance

- `journal.py` validates boot scope, JSON lines, timestamps, metadata and limits.
  Duplicate keys/cursors, mixed boot identities, malformed timestamps and oversized
  records fail closed. Unsupported/binary/missing MESSAGE values are counted as
  evidence gaps rather than rendered or treated as meaningful text.
- `incidents.py` applies explicit event signatures to normalized records. It does
  not collect files or execute commands beyond its injected runner boundary.
- `commands.py` permits only a 32-character lowercase hexadecimal boot identity in
  the new reader. No user-supplied switches, arbitrary filters or shell strings.
- `cli.py` presents history and findings without exposing raw messages. JSON is a
  command-specific schema version 1; existing status/check observation output is
  unchanged. Historical consumers must use the `command` field to select a schema.

Raw journal messages are read into bounded process memory only for explicit diagnose
commands. No report store, cache, file logger, export, telemetry or automatic upload
exists. Messages, hostnames, process names, unit names and device strings are never
copied into findings, error messages or terminal output. Record references include
validated boot ID, realtime/monotonic microseconds and a SHA-256 cursor fingerprint;
they do not expose the opaque raw cursor. Hashes aid comparison, not authentication.
Boot IDs/times are still potentially sensitive metadata: keep output local and review
before manually sharing it. Full original-log browsing is deferred to Evidence Explorer.

## Event rules and confidence

Every finding includes observation, evidence reference, reasoning, threshold (one
matching record), confidence, limitations, severity and investigation recommendations.
`cause_confidence` and overall `root_cause` remain Unknown in this milestone.

| Rule | Required evidence | What is confirmed |
| --- | --- | --- |
| kernel.oom | Kernel transport plus a specific global/cgroup OOM-kill message prefix | A matching kernel OOM-kill record exists |
| kernel.panic | Kernel transport plus `Kernel panic - not syncing:` prefix | A matching kernel panic record exists |
| kernel.io_error | Kernel transport plus a supported I/O-error prefix | A matching kernel I/O-error record exists, not a physical disk diagnosis |
| kernel.filesystem_error | Kernel transport plus the ext4-error prefix | A matching ext4 error record exists |
| systemd.start_job_failed | Trusted PID 1 / systemd metadata and the structured unit-start failure ID | A start job failed, not necessarily a runtime unit or whole-host outage |
| systemd.shutdown_marker | Trusted PID 1 / systemd metadata and the structured shutdown ID | A shutdown marker was recorded, not that shutdown completed |

An ordinary application's text mentioning panic/OOM or copying MESSAGE_ID does not
meet the trusted transport/process requirements. Root or kernel compromise remains
outside this integrity guarantee. The rules recognize a deliberately limited set
of signatures; other kernels, filesystems, producers, historical events or journald
metadata layouts may not match. No supported match does not imply no incident.

A shutdown marker can precede a later failure. Missing markers can reflect record
caps, permissions, rotation, a full disk, or an unflushed system freeze. Consequently
absence is Unknown, never proof of an unexpected reboot. No marker is called a
complete or normal shutdown. There is no automatic root-cause attribution.

## Timeline and completeness

Analyze at most 500 records from the accessible tail. Request 501 as a sentinel to
detect omitted earlier records. Report `record_limit_reached` explicitly; the byte
cap can reject the query before the record cap. Even an uncapped response is labeled
`bounded_tail`: permissions, retention and loss can hide records. Empty or failed
collection is unavailable, not a clean bill of health.

Order recognized events by the boot-local monotonic timestamp. Preserve realtime
microseconds separately because wall clocks can move backward. `timeline` contains
recognized event references only. `last_record` is the last accessible normalized
record in the bounded tail, not proof of the host's final event before a freeze.
Unsupported messages remain counted as gaps. Collection timestamps mark report
completion; current-boot results can change after collection.

## Tests and remaining work

All tests use invented JSON records or fake command results, including worst-case
501-record tails. They cover spoofing, false positives, shutdown uncertainty,
missing/denied history, cap detection, clock reversal, malformed/binary records,
boot-index races, raw-data exclusion and CPU/memory regression budgets. CI never
reads its host's real journal. A local environment without accessible boot history
can only verify graceful unavailability, not live detection accuracy.

Remaining phase 2 work: read/validate atop recordings through a justified existing
interface, correlate resource samples with journal events, verify persistence and
retention configuration, support richer history selection and complete evidence
inspection, and test on real supported Debian/Ubuntu targets using separately
reviewed sanitized material. Configuration recommendations must remain read-only;
any future changes require exact previews and explicit confirmation.

Primary references: [journalctl](https://www.freedesktop.org/software/systemd/man/253/journalctl.html),
[journal addressing fields](https://www.freedesktop.org/software/systemd/man/258/systemd.journal-fields.html),
and [systemd message IDs](https://github.com/systemd/systemd/blob/main/src/systemd/sd-messages.h).
