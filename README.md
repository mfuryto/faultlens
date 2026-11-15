# Faultlens

**Pre-release — bounded historical diagnostics, network observations and explainable security indicators.** Faultlens provides local, read-only Linux
system observations and dependency/logging checks. Journal-only analysis is an initial milestone, not full incident reconstruction.
A keyboard-driven local TUI is available. There is no packaged distribution or
supported production release.

The terminal workspace now follows UserDock's tabs, row-based tables and modal
navigation. See [workspace controls](docs/tui.md), [corrected acceptance](docs/architecture/phase-4-acceptance.md)
and [what the tool solves and still lacks](docs/stabilization.md). Earlier completion
claims for the generic curses browser are superseded by this implementation.

The target is Debian/Ubuntu Server with Python 3.11+. The CLI requires no external
Python packages. The optional Textual workspace has a complete wheel-hash lock in
requirements-tui.txt. Neither interface uses telemetry, cloud services or a database.

Install the optional workspace in an isolated environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-tui.txt
.venv/bin/python bin/faultlens tui
# Alternatively activate this environment before using ./bin/faultlens:
# . .venv/bin/activate
```

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
or inaccessible sources remain unavailable. See [preservation assessment](docs/architecture/phase-2-preservation.md).

History lists accessible boot IDs. Diagnose resolves a selected boot to an immutable
ID and analyzes at most 500 accessible tail records for specific kernel OOM, panic,
I/O/ext4 error, supported watchdog/blocked-task and OverlayFS reuse reports, and
structured systemd event signatures. Findings retain references,
reasoning, confidence and limitations. Raw journal messages are processed in bounded memory. `--show-evidence` exposes
retained original messages and cursors locally; summaries remain concise. The SSH
view includes identities and original candidate records. Nothing is saved or
uploaded automatically. Missing evidence and root causes
remain Unknown. See [journal analysis scope](docs/architecture/phase-2-journal.md)
and [kernel stall report rules](docs/architecture/phase-2-stall-rules.md).
Detector findings show checked reported measurements without task names or PID;
they do not establish a whole-system freeze or a cause.
[OverlayFS findings](docs/architecture/phase-2-overlayfs-rule.md) confirm a historical
layer-reuse warning, not an identified container or active current mount conflict.
Diagnose also reports the retained journal window, finding positions and clock-mapping
variation. Long intervals between records are not classified as missing logs or downtime.
See [chronology and coverage](docs/architecture/phase-2-reconstruction.md).
The default journal scope is everything accessible to the current user; it can lack
system evidence. `--system-journal` explicitly selects accessible system journals for
both listing and diagnosis without granting access. Use history with the same flag
when selecting boot indices. `diagnose --boot-id` can instead select an exact listed
identity across index changes; it cannot be combined with the other boot selectors.
See [stable boot selection](docs/architecture/phase-2-boot-selection.md).
`--until-us` can end the ordinary tail at a reference's exact `realtime_us` value
to inspect an older bounded window. Add `--since-us` to select an inclusive start,
or use it alone for a start-bounded tail. Reversed ranges are rejected; the 500-record
cap still applies. Targeted search scope stays unchanged. See
[historical journal windows](docs/architecture/phase-2-journal-window.md).
`incidents --boot-count 3` summarizes previous visible boots from one listing;
`--system-journal` preserves explicit scope and `--include-current` opts in to boot 0.
See [multi-boot overview](docs/architecture/phase-2-overview.md) and the
[phase 2 acceptance review](docs/architecture/phase-2-acceptance.md) for delivered
behavior, verification status and remaining product scope.
`diagnose --atop-date YYYYMMDD --atop-extended --json` opts in to bounded
[historical disk, network and process context](docs/architecture/phase-2-atop-extended.md).
Disk/interface names, PID/TGID, process names and wait channels are visible locally.
Both Atop profiles retain the recorded hostname and replay lines; use --json or
--show-evidence to inspect them. Recorded identity/activity does not establish a cause.
[Historical CPU accounting](docs/architecture/phase-2-atop-cpu.md) separates Atop
execution, idle, I/O-wait and steal shares. These interval measurements do not
establish disk failure, provider contention or an incident cause.
[Journal-driver loss findings](docs/architecture/phase-2-journal-loss.md) recognize
structured suppression and missed-kernel-message reports in the ordinary window.
They do not identify missing contents or establish full logging coverage.
Source counts and safe collection status are reported;
completeness remains unknown. See [journal scope](docs/architecture/phase-2-journal-scope.md).
`--search-events` adds two bounded selected-boot searches for kernel warning/error
candidates and supported structured systemd events. Results appear separately in
`event_search`; filtered spans are not continuous coverage. See [targeted search limits](docs/architecture/phase-2-targeted-search.md).
Each query also supplies `candidate_review` with recorded priority counts, reasons
for non-matches and at most 20 normalized example references. Unclassified does not
mean harmless; raw messages are not shown. See [candidate review](docs/architecture/phase-2-candidate-review.md).

`--atop-date YYYYMMDD` optionally reads a protected local recording through the
installed Atop tool, adding CPU/memory/swap samples and Possible wall-time overlaps.
It never asserts shared host/boot identity or a root cause. Atop remains optional;
without this explicit flag it is not invoked. See [Atop setup and limits](docs/architecture/phase-2-atop.md).
Recording begins only after Atop installation; old measurements cannot be recreated.
Filename-date gaps appear in `check --history`; replayed sample intervals add Possible
coverage gaps to `diagnose --atop-date`. Neither proves a recorder outage or continuity.

`diagnose --pstore` optionally inspects bounded live pstore records for panic signatures.
It shows redacted references, never raw crash text, and does not associate records with
the selected boot. Access denial or no visible records does not exclude a crash.
No extra package, root execution or system changes are required by Faultlens; restricted
records remain unavailable. See [coverage and pstore scope](docs/architecture/phase-2-coverage-pstore.md).
`--pstore-archive` separately requests bounded raw records from the fixed systemd
archive; it can be combined with `--pstore`. Reconstructed copies and unsupported
layouts are excluded. See [archive scope](docs/architecture/phase-2-pstore-archive.md).

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
not proof of host health. See [measurement validation](docs/validation.md).

One-shot CLI exit codes: 0 means a report was rendered (including partial/unavailable observations),
1 means unsupported platform or collection/rendering failure, 2 means invalid arguments,
and 130 means interrupted collection. Inspect observation states for warnings or gaps;
exit 0 does not assert that the system is healthy. TUI exit 0 means orderly exit.
`health` aliases check; calendar history filters and configuration changes remain unimplemented. The TUI now exposes the existing
read-only adapters; see [terminal navigation](docs/tui.md).

Pstore and its systemd archive now expose collected relative filenames, file metadata
and original content locally. Use --json or --show-evidence for full content;
binary/expansion-heavy content is losslessly base64-encoded. Collection and signature
analysis availability are separate. See [pstore admin views](docs/architecture/phase-3-pstore-admin.md).

See [dependencies and feature requirements](docs/dependencies.md) before installing
optional tools. Executable availability alone does not prove feature readiness.

`network` and `security` take two bounded local counter snapshots for per-interface
rates and selected TCP indicators. Confirmed counter growth never confirms an attack;
security assessment remains Unknown. Counter-only collection has no endpoints;
`--sockets` adds numeric local TCP/UDP endpoints. No packet capture or external
probes are performed. Opt-in SSH journal observations and local original evidence views are described in
[SSH analysis](docs/architecture/phase-3-ssh.md). Opt-in [firewall log observations](docs/architecture/phase-3-firewall.md) preserve
reported UFW labels and packet context, without claiming verified verdicts. Active
policy inspection, broader authentication methods and verified attack attribution remain future work. See [phase 3 network scope](docs/architecture/phase-3-network.md).

Optional current TCP/UDP endpoints (numeric addresses and ports remain visible):

```sh
./bin/faultlens network --sockets
./bin/faultlens security --sockets --json
```

This uses the locally installed `ss` without remote probes or elevation. A binding
is not proof of external reachability. See [socket scope](docs/architecture/phase-3-sockets.md).

Phase 3 CLI implementation is complete within its documented source bounds.
[Acceptance and detection rules](docs/architecture/phase-3-acceptance.md) describe
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
retain original objects. See [readable results](docs/readable-results.md).

## Interactive terminal interface

```sh
./bin/faultlens tui
```

With interactive input/output, `./bin/faultlens` also starts the TUI; redirected
invocation retains one-shot status behavior. Source tabs load when opened. Left/Right
changes sections, Up/Down selects rows, Enter opens details and Esc returns. Use r to
refresh, ? for help and q to quit. Optional sources
are controlled by per-user preferences, saved on valid changes. Diagnostic evidence is
not persisted and server configuration is not changed. See [preference storage](docs/tui.md#saving-preferences).
Long original evidence remains inspectable with lossless terminal escaping.
See [the TUI guide](docs/tui.md), [Phase 4 acceptance](docs/architecture/phase-4-acceptance.md)
and [release readiness](docs/release-readiness.md). Real target VPS deployment
acceptance and owner-approved licensing remain gates before production publication.

## Combined server checks

```sh
python3 scripts/server_check.py
```

Run as the non-root checkout owner. The default read-only summary explains what
worked, what could not be tested and what follow-up may be needed. Related gaps are grouped without hiding failures.
Use --details for every technical check or --json for structured results. The script
does not install tools or change server configuration. Optional --atop-date/--pstore,
--live-only, --json and --details are documented in [server testing](docs/server-check.md).
Repository checks are automatically skipped when run as root or a non-owner.

## Develop and verify

Use only `staging` and `main`; PRs to main require the baseline, analysis and CodeQL
findings checks. Run development checks as the user who owns the checkout, without
root. The tests and benchmarks use synthetic data and do not require access to real
system logs. Git can refuse a checkout owned by another user; switch to its owner
instead of changing repository trust or permissions just to run the checks.
Synthetic tests never collect diagnostics from the CI host.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/security_check.py
python3 scripts/benchmark.py --iterations 10
python3 scripts/vps_acceptance.py --iterations 3
```

Security checks inspect tracked files and all locally reachable Git history. Stage new
files before running the tracked-file scan; fetch all refs before a publication audit.
No dependency installation is needed. Benchmark methodology and initial measurements
are in [resource benchmarks](docs/benchmarks.md).

Read [contributing](CONTRIBUTING.md), [private vulnerability reporting](SECURITY.md),
[product specification](docs/product-specification.md),
[Phase 1 decisions and limitations](docs/architecture/phase-1.md),
[threat model](docs/security/architecture.md), and
[repository controls](docs/security/hardening-status.md).

## Licensing

No license has been selected or granted. Do not assume permission to redistribute.
A license requires explicit owner approval before a licensed release.
