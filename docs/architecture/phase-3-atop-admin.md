# Local administrator views for Atop evidence

Both Atop profiles now expose `recorded_hostname` and `source_records` for every
retained validated sample. The extended profile also exposes device/interface names
and per-record process/thread details. This removes earlier identity omissions from
the adapter; local operator visibility is not restricted by a privacy filter.

```sh
./bin/faultlens diagnose --boot 0 --atop-date 20260101 --atop-extended --json
./bin/faultlens diagnose --boot 0 --atop-date 20260101 --atop-extended --show-evidence
```

Choose the intended recording date and existing journal permissions. JSON includes
the local views directly. Text output stays concise by default; --show-evidence prints
each complete retained Atop sample as terminal-safe JSON alongside journal evidence.
No extra query, process, package, privilege or file is introduced by the view.

## Exposed identities and source records

- Basic/extended samples include the hostname reported by Atop. It is an observation,
  not a verified match to the current host or selected journal boot.
- Each normalized disk/interface row includes its recorded name as well as the
  existing fingerprint. Fingerprints remain comparison aids, not anonymization.
- Extended `process_details` includes PID, TGID, name, state, process/thread flag,
  wait channel, machine tick units and reported CPU/memory/swap/fault measurements.
- `source_records` preserves the accepted native lines, including CPU/MEM/SWP and
  all requested extended rows, plus RESET/SEP markers. It does not reconstruct the
  original binary recording or claim omitted/unrequested labels were collected.

The fixed extended replay still uses Atop -Z. Spaces in process names/wait channels
can therefore appear as underscores; their original spacing cannot be reconstructed
from that output. Native lines preserve the representation actually received, not
a fabricated original spelling. Command lines/UID ownership/network endpoints are
not collected by this profile. More source labels require their own validated adapter.
Blank separator lines are not records and are not retained.

## Resource and attribution semantics

`measurement_scope` distinguishes recorded_interval, since_boot and
exited_accounting_unlocalized process data. `included_in_aggregate` explicitly marks
which rows contribute to existing interval process sums. Thread, exited and RESET
rows remain visible locally but do not silently enter those sums. Reported resource
values remain labeled as such; shared memory, recording/accounting semantics and
sampling intervals limit interpretation.

PID reuse, process renaming and unverified recording host/boot identity prevent
longitudinal identity guarantees or assigning blame merely from a PID/name. Existing
Possible wall-clock correlation never becomes proof of an incident cause. RESET
and exited measurements must not be presented as ordinary interval resource rates.

All existing byte/sample/cardinality limits, pairing validation, descriptor trust,
isolated execution and read-only behavior remain in force. Invalid/truncated input
is unavailable rather than partially interpreted. Native stderr remains outside
this view. No larger query or permission change hides a source failure.

## Terminal safety and verification

Names and source lines are rendered with JSON escaping in text/JSON modes. This
preserves decoded values while preventing ANSI/OSC/bidi controls from operating the
terminal. No evidence is saved, exported or uploaded automatically. Repository/CI
fixtures remain invented even though administrators may inspect real local data.

Tests cover identities, units, original line preservation, recorded hostnames,
thread/exited/RESET visibility without double counting, and escaped format controls.
The maximum-cardinality benchmark verifies 256 local process details with 32 named
disks and 32 named interfaces. Native extended replay compatibility and full pstore/
TUI evidence views remain separate validation/implementation tasks.
