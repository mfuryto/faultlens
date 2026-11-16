# Faultlens CLI reference

Detailed commands, collection bounds, exit codes and evidence interpretation. For
installation and a short introduction, start with the [README](../README.md).
TUI navigation and saved preferences are covered in the [workspace guide](tui.md).

## Run from source

From a trusted checkout, as an ordinary user:

```sh
./bin/faultlens
./bin/faultlens status
./bin/faultlens status --json
./bin/faultlens status --sample-seconds 0.2
./bin/faultlens check
./bin/faultlens check --json
./bin/faultlens check --history
./bin/faultlens check --history --json
./bin/faultlens incidents --system-journal --boot-count 3
./bin/faultlens network --json
./bin/faultlens security --json
./bin/faultlens history
./bin/faultlens history --system-journal
./bin/faultlens diagnose --boot 0 --system-journal --search-firewall --json
./bin/faultlens diagnose --boot 0 --system-journal --search-ssh --json
./bin/faultlens diagnose --boot 0 --system-journal --show-evidence --json
./bin/faultlens diagnose --previous-boot
./bin/faultlens diagnose --previous-boot --pstore
./bin/faultlens diagnose --previous-boot --pstore-archive --json
./bin/faultlens diagnose --boot -2 --json
./bin/faultlens diagnose --boot 0 --system-journal --json
./bin/faultlens diagnose --boot 0 --system-journal --search-events --json
./bin/faultlens diagnose --previous-boot --atop-date 20261114 --json
```

`python3 -m faultlens` is an equivalent entry point from the repository root. The
launcher can also be invoked by absolute path from another directory. No installation
or root access is required. Python source imports may create normal bytecode caches;
the launcher disables them. Faultlens does not save reports or change system settings.

Status covers sampled aggregate CPU, load, RAM/swap, root filesystem capacity,
cumulative per-device I/O and interface counters, visible process count, kernel/boot
information and the systemd manager state where available. `check` inspects optional
utilities, journal directory presence, visible prior boots, and journald/atop service
state. It never reads out raw log entries or claims that a directory proves recording.

`check --history` additionally inspects explicit merged journald settings, literal Atop
defaults, log filesystem capacity and bounded recording metadata. It supplies review
recommendations without changing settings. Configuration snapshots do not prove running
state or retained coverage. The merged-config probe uses portable cat-config without --tldr; unsupported
or inaccessible sources remain unavailable. See [preservation assessment](architecture/phase-2-preservation.md).

History lists accessible boot IDs. Diagnose resolves a selected boot to an immutable
ID and analyzes at most 500 accessible tail records for specific kernel OOM, panic,
I/O/ext4 error, supported watchdog/blocked-task and OverlayFS reuse reports, and
structured systemd event signatures. Findings retain references,
reasoning, confidence and limitations. Raw journal messages are processed in bounded memory. `--show-evidence` exposes
retained original messages and cursors locally; summaries remain concise. The SSH
view includes identities and original candidate records. No diagnostic evidence is saved or
uploaded automatically. Missing evidence and root causes
remain Unknown. See [journal analysis scope](architecture/phase-2-journal.md)
and [kernel stall report rules](architecture/phase-2-stall-rules.md).
Detector findings show checked reported measurements without task names or PID;
they do not establish a whole-system freeze or a cause.
[OverlayFS findings](architecture/phase-2-overlayfs-rule.md) confirm a historical
layer-reuse warning, not an identified container or active current mount conflict.
Diagnose also reports the retained journal window, finding positions and clock-mapping
variation. Long intervals between records are not classified as missing logs or downtime.
See [chronology and coverage](architecture/phase-2-reconstruction.md).
The default journal scope is everything accessible to the current user; it can lack
system evidence. `--system-journal` explicitly selects accessible system journals for
both listing and diagnosis without granting access. Use history with the same flag
when selecting boot indices. `diagnose --boot-id` can instead select an exact listed
identity across index changes; it cannot be combined with the other boot selectors.
See [stable boot selection](architecture/phase-2-boot-selection.md).
`--until-us` can end the ordinary tail at a reference's exact `realtime_us` value
to inspect an older bounded window. Add `--since-us` to select an inclusive start,
or use it alone for a start-bounded tail. Reversed ranges are rejected; the 500-record
cap still applies. All requested journal searches, including broader event, SSH and
firewall searches, use the same inclusive receipt-time bounds. See
[historical journal windows](architecture/phase-2-journal-window.md).
`incidents --boot-count 3` summarizes previous visible boots from one listing;
`--system-journal` preserves explicit scope and `--include-current` opts in to boot 0.
See [multi-boot overview](architecture/phase-2-overview.md) and the
[phase 2 acceptance review](architecture/phase-2-acceptance.md) for delivered
behavior, verification status and remaining product scope.
`diagnose --atop-date YYYYMMDD --atop-extended --json` opts in to bounded
[historical disk, network and process context](architecture/phase-2-atop-extended.md).
Disk/interface names, PID/TGID, process names and wait channels are visible locally.
Both Atop profiles retain the recorded hostname and replay lines; use --json or
--show-evidence to inspect them. Recorded identity/activity does not establish a cause.
[Historical CPU accounting](architecture/phase-2-atop-cpu.md) separates Atop
execution, idle, I/O-wait and steal shares. These interval measurements do not
establish disk failure, provider contention or an incident cause.
[Journal-driver loss findings](architecture/phase-2-journal-loss.md) recognize
structured suppression and missed-kernel-message reports in the ordinary window.
They do not identify missing contents or establish full logging coverage.
Source counts and safe collection status are reported;
completeness remains unknown. See [journal scope](architecture/phase-2-journal-scope.md).
`--search-events` adds two bounded selected-boot searches for kernel warning/error
candidates and supported structured systemd events. Results appear separately in
`event_search`; filtered spans are not continuous coverage. See [targeted search limits](architecture/phase-2-targeted-search.md).
Each query also supplies `candidate_review` with recorded priority counts, reasons
for non-matches and at most 20 normalized example references. Unclassified does not
mean harmless; raw messages are not shown. See [candidate review](architecture/phase-2-candidate-review.md).

`--atop-date YYYYMMDD` optionally reads a protected local recording through the
installed Atop tool, adding CPU/memory/swap samples and Possible wall-time overlaps.
It never asserts shared host/boot identity or a root cause. Atop remains optional;
without this explicit flag it is not invoked. See [Atop setup and limits](architecture/phase-2-atop.md).
Recording begins only after Atop installation; old measurements cannot be recreated.
Filename-date gaps appear in `check --history`; replayed sample intervals add Possible
coverage gaps to `diagnose --atop-date`. Neither proves a recorder outage or continuity.

`diagnose --pstore` optionally inspects bounded live pstore records for panic signatures.
It retains source references and original crash content locally without associating
records with the selected boot. Use --json or --show-evidence to inspect full content. Access denial or no visible records does not exclude a crash.
No extra package, root execution or system changes are required by Faultlens; restricted
records remain unavailable. See [coverage and pstore scope](architecture/phase-2-coverage-pstore.md).
`--pstore-archive` separately requests bounded raw records from the fixed systemd
archive; it can be combined with `--pstore`. Reconstructed copies and unsupported
layouts are excluded. See [archive scope](architecture/phase-2-pstore-archive.md).

Evidence can be sensitive even in summary form. Output stays on your terminal/stdout;
review it before manually redirecting or sharing it. No automatic exports or uploads
exist. Missing/denied/malformed sources are explicitly unavailable, not healthy zeros.
JSON includes units, source, confidence, explanations, thresholds and limitations.
CPU/network counters may reflect a host or namespace rather than cgroup limits.

For an optional local consistency check against trusted `free`, `df`, `uname`'s
kernel interface and the Linux boot clock:

```sh
python3 scripts/validate_local.py
python3 scripts/validate_local.py --json
```

The comparison prints only PASS/MISMATCH/UNAVAILABLE and fixed explanations, never
raw machine values. It saves nothing and does not run automatically in CI. Validation
exit codes are separate: 0 means all eight comparisons matched within documented
tolerances, 1 means a mismatch, 2 means incomplete/unsupported validation, and 130
means interrupted. A mismatch can reflect collection-time differences; a pass is
not proof of host health. See [measurement validation](validation.md).

One-shot CLI exit codes: 0 means a report was rendered (including partial/unavailable observations),
1 means unsupported platform or collection/rendering failure, 2 means invalid arguments,
and 130 means interrupted collection. Inspect observation states for warnings or gaps;
exit 0 does not assert that the system is healthy. TUI exit 0 means orderly exit.
`health` combines current operational readings, a bounded failed-service listing and
diagnostic readiness; `check` remains readiness-only. Calendar history filters and
configuration changes remain unimplemented. The TUI now exposes the existing
read-only adapters; see [terminal navigation](tui.md).

Pstore and its systemd archive now expose collected relative filenames, file metadata
and original content locally. Use --json or --show-evidence for full content;
binary/expansion-heavy content is losslessly base64-encoded. Collection and signature
analysis availability are separate. See [pstore admin views](architecture/phase-3-pstore-admin.md).

See [dependencies and feature requirements](dependencies.md) before installing
optional tools. Executable availability alone does not prove feature readiness.

`network` and `security` take two bounded local counter snapshots for per-interface
rates and selected TCP indicators. Confirmed counter growth never confirms an attack;
security assessment remains Unknown. Counter-only collection has no endpoints;
`--sockets` adds numeric local TCP/UDP endpoints. No packet capture or external
probes are performed. Opt-in SSH journal observations and local original evidence views are described in
[SSH analysis](architecture/phase-3-ssh.md). Opt-in [firewall log observations](architecture/phase-3-firewall.md) preserve
reported UFW labels and packet context, without claiming verified verdicts. Active
policy inspection, broader authentication methods and verified attack attribution remain future work. See [phase 3 network scope](architecture/phase-3-network.md).

Optional current TCP/UDP endpoints (numeric addresses and ports remain visible):

```sh
./bin/faultlens network --sockets
./bin/faultlens security --sockets --json
```

This uses the locally installed `ss` without remote probes or elevation. A binding
is not proof of external reachability. See [socket scope](architecture/phase-3-sockets.md).

Phase 3 CLI implementation is complete within its documented source bounds.
[Acceptance and detection rules](architecture/phase-3-acceptance.md) describe
current UDP/TCP pressure counters, SSH failure bursts, logged multi-port/UDP
patterns and historical traffic-rate anomalies. A possible indicator is never a
confirmed attack or root cause. Historical rules analyze only evidence explicitly
requested with the existing options:

```sh
./bin/faultlens diagnose --previous-boot --system-journal --search-ssh --search-firewall --json
./bin/faultlens diagnose --previous-boot --atop-date 20260101 --atop-extended --json
```

Replace the example recording date with an existing local recording. Historical
traffic comparison needs at least six comparable contiguous samples; missing
history remains explicit rather than generating an all-clear.

## Understand readings and findings

Default CLI results and the TUI explain what was observed, what it can mean and
what to investigate next. Missing evidence is distinct from a failure; confirmed
reports are distinct from confirmed causes. Original identities and measurements
remain inspectable without privacy masking.

```sh
./bin/faultlens status
./bin/faultlens status --details
./bin/faultlens diagnose --previous-boot --show-evidence --json
```

Use --details for the existing technical text view, --json for the unchanged
structured schema, and --show-evidence for retained ordinary journal originals.
Optional sources still require their existing flags. In the TUI, open Summary and
next steps or select a reading/finding; Technical details and Evidence Explorer
retain original objects. See [readable results](readable-results.md).

Readable `diagnose` output starts with a fault-investigation narrative: actual
retained message excerpts, UTC receipt timestamps, explanations and next steps. It
retains evidence locally in memory for this view. `--json` keeps its existing
explicit `--show-evidence` contract; `--details` remains the technical view.
`incidents` additionally retains up to three 512-character report excerpts per
examined boot with references and named problems. These are administrator data,
not anonymized examples. Complete originals are available through explicit diagnosis.
Atop replay covers a bounded two-hour window around the last retained journal receipt
in one explicitly dated recording; other capture limits and clock protections remain.

## Select an incident by date and time

Use explicit timezone offsets or UTC; Faultlens does not guess the host timezone:

```sh
./bin/faultlens diagnose --previous-boot --system-journal --search-events \
  --since '2026-11-14T23:20:00+01:00' \
  --until '2026-11-14T23:40:00+01:00'
```

Replace the example dates with the incident period and select the relevant boot.
`--since`/`--until` accept ISO dates with `T` or a space, hour/minute, optional
seconds and at most six fractional digits, followed by `Z` or `+HH:MM`/`-HH:MM`.
Timezone-free and relative expressions are rejected. The corresponding `--since-us`
and `--until-us` options remain exact Unix microseconds; each human/numeric pair is
mutually exclusive. Inclusive bounds apply to every requested journal query before
the record cap and are validated again on returned records. Empty bounded results
do not fall back to a whole boot.

Atop remains a separately labeled two-hour context window, and pstore remains
unattributed to a time/boot. This does not promise complete evidence for the selected
period. See [time-selection design](architecture/incident-time-window.md).
