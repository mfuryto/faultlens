# Readable Faultlens results

The default CLI output explains collected readings and findings in plain English.
It separates the observation, its meaning, possible next steps and important evidence
limits. It does not change detectors, thresholds, confidence, source selection or
permissions. There is no overall healthy/secure verdict based on absent findings.

```sh
./bin/faultlens status
./bin/faultlens health --history
./bin/faultlens network --sockets
./bin/faultlens diagnose --previous-boot --search-ssh --search-firewall
```

Readings use understandable names and units: bytes may be displayed as KiB/MiB/GiB,
intervals as seconds/minutes/hours, and the reported kernel boot time as UTC. These
are rounded presentation values; exact numbers and original units remain available
in technical/JSON views. Load averages are task counts, not CPU percentages, and
swap use alone does not establish current memory pressure. Space warnings describe
capacity, not filesystem integrity or an instruction to delete files.

Unavailable tools/data and unverified defaults are explained without asserting that
a server is broken. Missing explicit journald assignments may use defaults; the
loaded effective settings remain unverified. A failed journal query does not establish
permission denial or absent history. Receipt bounds and the selected immutable boot
identity retain their source meaning; no fallback source or extra query is added.

## Findings and follow-up

When relevant, follow-up steps include optional read-only commands for current
filesystem capacity, failed units, recorder/journal service state, journal configuration
assignments, network snapshots and overlay mounts. Commands are fixed suggestions;
host messages, unit names and mount paths are never interpolated into them. Nothing
executes automatically. Run Faultlens commands from a trusted checkout and use trusted
native tools with existing authorized access. Missing optional tools are not an
instruction to install packages or change permissions.

These checks describe the present host, not necessarily its condition at the time of
a recorded incident. For example, an overlay warning suggests
`findmnt --json --list -t overlay -o TARGET,OPTIONS`; current mounts cannot prove which
mounts existed during an earlier warning. A failed service listing can be empty after
a service recovered. Configuration assignments do not establish loaded settings.

If the main journal source is unavailable, the summary suggests
`journalctl --list-boots --no-pager`, retaining `--system` when system scope was selected.
This exposes the native tool's explanation without assuming every failure means denied
access. It does not grant access, change groups, request elevation or infer absent history.
The same advice appears in the TUI explanation views; JSON and technical evidence stay
unchanged.

Each explained finding retains the source confidence and distinguishes the reported
event from its cause. For example, an OOM report means the kernel reported killing a
process because of memory shortage/limits; it does not identify why memory ran out or
prove the cause of a whole-host freeze. Shutdown initiation is not shutdown completion.
A firewall label is not a verified final packet verdict. An SSH acceptance report is
not proof of an authorized full session or compromise. Heuristic security indicators
remain Possible, with attack/cause unverified.

Repeated reports with the same source/rule/confidence/severity are grouped in the
CLI explanation. Their count is a number of matched reports, not distinct incidents.
Main, targeted, SSH/firewall and derived-security locations remain separate and are
identified in the display; overlapping reports are not independent corroboration.
The complete individual findings, references, thresholds and original source results
remain inspectable. No username, peer, port or original is masked for privacy.

Optional socket snapshots show the collected numeric local/peer endpoints and states
without concealing addresses. A local binding does not prove Internet reachability.
Missing rates after resets/interface changes are described as not comparable, never
as zero traffic. Historical traffic comparison needs existing comparable samples;
the frontend never invents a baseline, widens a replay window or changes recording.

Crash records are summarized separately. Panic signatures remain Possible, archive/live
fragments are not automatically attributed to the selected boot, and duplicates need
not corroborate each other. Binary/unsupported analysis is distinguished from source
readability. Empty/unavailable crash evidence does not rule out a crash.

## Technical measurements and originals

```sh
./bin/faultlens status --details
./bin/faultlens diagnose --previous-boot --details
./bin/faultlens diagnose --previous-boot --show-evidence
./bin/faultlens diagnose --previous-boot --show-evidence --json
```

--details selects the existing technical text view: exact recorded measurements,
source references, detector reasoning, thresholds and limitations. --show-evidence
continues to request retained ordinary journal originals and show recording/crash
content in the technical text view. Optional Atop/pstore sources still need their
existing explicit flags. No new source is read just to create an explanation.

--json preserves the original report schema and source fields. Derived prose is
presentation only and is not inserted into the structured diagnostic model. Scripts
should use JSON rather than parse the new default text. No exit-code decision is
changed: an available/partial/unavailable rendered report can still exit 0 without
asserting host health. Read failures and invalid arguments retain their existing codes.

## TUI explanations and evidence

The source pages start with **Summary and next steps**. Measurement rows have plain
names and readable values; Enter opens **Observed**, **What it means**, **What you can
do**, confidence, limits and **Technical details**. Normalized finding lists similarly
open explained findings with a direct reference to the original finding. Advice and
limits can be opened and paged without losing their underlying fields.

The Diagnostics and Security pages expose explained source findings. Main timeline
rows show time relative to the first retained record, not boot start; equal-timestamp
ordering stays unresolved. Gaps do not establish lost logging, downtime or a freeze.
The Evidence Explorer and Full report entries remain complete raw trees, preserving
all original collected identities, messages, binary encodings and metadata. Session
settings have readable labels but retain the same typed keys and collection behavior.

Only normalized observation/finding locations receive diagnostic explanations.
Original message objects are never duck-typed into trusted guidance, even if an
original JSON message contains fields named rule_id, confidence or recommendations.
All terminal data is escaped reversibly; prose is never interpreted as terminal markup,
shell commands or configuration instructions to execute automatically. The frontend
retains one report and browses source values by reference rather than copying evidence.
