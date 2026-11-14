# Phase 2: preservation assessment

`faultlens check --history` adds an opt-in, read-only configuration and metadata
assessment. Ordinary `check`, history and diagnose keep their existing collection
scope. No service is installed, enabled, restarted or reconfigured. No recording
is replayed by this assessment and no report is saved or transmitted.

## Evidence and interpretation

The fixed command `systemd-analyze cat-config --tldr systemd/journald.conf` resolves
vendor configuration and ordered drop-ins. The comment-filtered form requires
systemd 255 or newer. Unsupported commands, unknown boundaries, malformed structure,
byte limits or timeouts produce unavailable evidence; there is no guessed fallback.
The parser resets section scope at each source boundary and interprets only explicit
Storage, SystemMaxUse, SystemKeepFree, RuntimeMaxUse, RuntimeKeepFree and MaxRetentionSec
assignments in Journal sections. Later assignments replace earlier observations.
Unsupported final expressions become unknown rather than retaining a previous value.
Only bounded integer binary sizes and a subset of whole-number duration units are
normalized. Explicit zero is preserved without claiming unlimited retained history.

These are configuration snapshots for the default namespace, not proof of loaded
settings, flushing, writable persistent storage or actual retention. Unspecified
settings have compiled defaults that Faultlens does not infer. Volatile or disabled
storage configuration raises a warning about the observed configuration only.

`/etc/default/atop` is read as bounded data, never sourced or executed. Only literal
assignments are accepted. LOGINTERVAL and LOGGENERATIONS are hints; service unit
arguments, environment overrides and rotation behavior remain unverified. LOGPATH
is reduced to a boolean comparison with the supported standard directory; arbitrary
paths and other configuration values are not emitted. Recommendations ask the user
to compare recorded intervals and measure overhead before changing sampling.

Protected default `/var/log/journal` and `/var/log/atop` directories are opened through
root-owned ancestors without following symlinks. Filesystem totals and available
bytes come from their pinned descriptors. These values describe the filesystem,
not journal consumption or the number of days it can retain. Inaccessible or unsafe
directories remain unavailable; no elevation is attempted.

The Atop inventory enumerates at most 512 directory entries without reading recording
contents or traversing subdirectories. It reports aggregate logical size, valid file
counts, empty/oversized/unsafe/excluded counts and oldest/newest filename dates.
Only root-owned regular files without group/world write permissions qualify. Compressed
and custom names are excluded. An incomplete enumeration is unavailable, not a partial
success. Files can change during collection; dates and sizes do not establish host,
boot identity, continuous coverage, authenticity or usable samples.

## Bounds and remaining work

The configuration subprocess inherits the fixed trusted executable catalog, minimal
environment, no shell/stdin, two-second deadline and 256 KiB combined output limit.
Configuration parsing also limits line lengths/counts; the Atop defaults file is at
most 16 KiB. Filesystem calls depend on the kernel and do not have subprocess deadlines.
No raw configuration, custom paths or directory names appear in reports. Normalized
settings, dates and capacity summaries can still be sensitive; review before sharing.

Observation JSON gains an additive `recommendations` array, also rendered in text.
Warnings and unavailable observations do not change the existing report exit-code
contract. Nothing in this milestone establishes root cause or completes phase 2.
Loaded-state verification, namespace/custom paths, rotation verification, broader archive compatibility,
full shutdown verification and explicitly approved configuration changes remain future work.

Synthetic tests cover overrides, section boundaries, limits, unsupported expressions,
shell rejection, redaction, missing sources and unsafe metadata. The benchmark adds
`check-history`; live smoke tests inspect only counts and states and save no host data.

References: [systemd-analyze](https://www.freedesktop.org/software/systemd/man/255/systemd-analyze.html),
[journald configuration](https://www.freedesktop.org/software/systemd/man/258/journald.conf.html),
[Atop service](https://github.com/Atoptool/atop/blob/master/atop.service),
[Atop rotation](https://github.com/Atoptool/atop/blob/master/atop.daily).

The next milestone adds [filename/sample coverage hints and live pstore analysis](phase-2-coverage-pstore.md).
