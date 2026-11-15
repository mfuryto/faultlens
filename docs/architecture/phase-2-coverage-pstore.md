# Phase 2: coverage hints and opt-in pstore analysis

This milestone adds evidence about possible history gaps and a bounded pstore
panic-signature reader. It does not establish continuous coverage, a root cause,
normal shutdown or a shared boot between independent sources.

## Recording history

`check --history` adds `filename_coverage` to the existing Atop inventory. After a
complete bounded enumeration, it sorts distinct valid filename dates and reports
missing calendar-date ranges strictly between the earliest and latest dates. It
never expands a multi-year range into individual days. A missing filename date
raises a warning about a Possible gap, not a confirmed recorder outage. No expected
retention schedule is assumed. Downtime, clock/date changes, rotation, compression,
custom paths and excluded/unsafe files can explain missing names. Empty or oversized
files still count as filename presence; they do not establish usable recordings.
Zero or one filename date cannot establish continuity. There is no inference outside
the observed range. Enumeration limits/errors still discard incomplete inventories.

`diagnose --atop-date YYYYMMDD` adds `atop.coverage` for the already collected,
validated samples inside the existing 30-minute window. For consecutive non-RESET
samples, an interval starts at its timestamp minus its reported period. If that
start is later than the previous sample's timestamp, the uncovered interval is
reported as a Possible gap with sample references and duration. Overlapping intervals
are counted separately. No inference is made across either side of RESET, outside
the retained samples or about the intended sampling schedule. Wall-clock changes,
restarts and interval semantics remain alternatives to missing records. Coverage
analysis adds no external commands and does not upgrade event/cause confidence.

## Pstore collection and reporting

Use `diagnose --pstore` to request live `/sys/fs/pstore` inspection. It is independent
of journal collection and runs even if the requested boot is not visible. JSON adds
a separate `pstore` object; its state must be inspected independently of the journal
state. No pstore data is collected without this flag. No new package is required.

The reader walks fixed root-owned, non-group/world-writable directories using pinned
read-only descriptors, O_DIRECTORY and O_NOFOLLOW. It enumerates at most 64 entries,
reads at most eight supported regular root-owned files, limits each to 128 KiB and
the accepted snapshot to 512 KiB. Files are opened relative to the pinned directory
with O_NOFOLLOW and O_NONBLOCK; FIFO/device/symlink and unsafe permission cases are
rejected before reading. Reads are capped independently of reported file size.
Metadata changes during a read reject the snapshot. Kernel filesystem calls have
no hard wall-time deadline; a compromised or stalled kernel remains outside these
userspace bounds. No mount, unlink, archival, decompression, recursive walk, elevation,
external command, report file or service change is performed.

Supported names are numeric `dmesg-ramoops`, `dmesg-efi`, `dmesg-efi_pstore`,
`dmesg-erst`, `dmesg-pstore-blk` and `console-ramoops` records. Other names, including
compressed records, ftrace and pmsg, are counted as excluded and never opened.
Strict UTF-8 text without NUL is required for signature analysis, with at most
4096 lines and 4096 characters per line. Unsupported/binary content remains
inspectable with analysis unavailable. Changing, oversized, unsafe or unreadable
sources invalidate the entire snapshot; no partial source results survive.
Absent/changed and access-denied states are reported explicitly. An empty readable
directory means no supported records were visible, not that pstore was operational
or no crash occurred. Mount/backend availability is not inferred from directory presence.

Only line-anchored `Kernel panic - not syncing:` signatures with optional kernel
priority/timestamp prefixes are recognized. Records report an index, SHA-256 of the
read bytes, byte count and signature line numbers. Local administrator views now
also expose relative filenames, observed metadata and lossless original content;
see [pstore administrator evidence](phase-3-pstore-admin.md). Signature confidence is Possible; all root causes
remain Unknown. No record is associated with the selected boot or assigned an event
time. Hashes support repeatability but do not authenticate root/kernel-controlled
input; even normalized references should be reviewed before sharing. This is a narrow
panic-signature milestone, not general oops decoding, stack analysis or crash diagnosis.

Systemd can archive and remove pstore records after boot; this reader does not inspect
`/var/lib/systemd/pstore` or change archiving policy. Missing live records therefore
cannot exclude archived evidence. Permissions commonly prevent unprivileged access;
Faultlens returns unavailable without requesting root or weakening permissions.

## Validation and remaining scope

Synthetic tests cover calendar boundaries, gaps, overlaps, resets, absent history,
local evidence preservation, opt-in behavior, independent source failures, fixed descriptor walks,
symlinks/FIFOs, unsafe metadata, changes, decoding and enumeration/size limits.
The synthetic pstore benchmark processes eight invented records totaling 512 KiB
alongside the bounded journal. No actual crash data is included in tests or CI.
A live smoke test verified graceful access denial and a complete one-file Atop
inventory; it does not establish live panic-detection accuracy.

Future work includes reviewed archived-pstore support, backend capability assessment,
additional narrowly tested signatures and target-host compatibility testing. This
milestone does not complete phase 2 or authorize any system configuration changes.

Primary references: [kernel ramoops documentation](https://www.kernel.org/doc/html/latest/admin-guide/ramoops.html),
[kernel pstore block documentation](https://www.kernel.org/doc/html/latest/admin-guide/pstore-blk.html),
[systemd-pstore](https://www.freedesktop.org/software/systemd/man/254/systemd-pstore.html),
[pstore configuration](https://www.freedesktop.org/software/systemd/man/255/pstore.conf.d.html).

A subsequent milestone adds [independent opt-in systemd archive inspection](phase-2-pstore-archive.md).
The live reader described above retains its original scope.
