# Pstore administrator evidence views

The local administrator evidence milestone now covers retained journal/SSH messages,
Atop replay records and both supported pstore sources. This completes that CLI view
step; it does not complete phase 3 attack analysis or the future TUI.

```sh
./bin/faultlens diagnose --previous-boot --pstore --pstore-archive --json
./bin/faultlens diagnose --previous-boot --pstore --pstore-archive --show-evidence
```

Pstore sources remain independently opt-in and need no selected-boot attribution to
be inspected. Existing Linux permissions apply. No mounting, deletion, privilege
escalation, archiving, export or upload is performed. Text summaries show source
metadata and how to inspect content; JSON and --show-evidence expose full retained
contents without privacy-based masking.

## Source names and metadata

Each result identifies its fixed source root: /sys/fs/pstore or
/var/lib/systemd/pstore. Native collection preserves each supported filename; archive
paths retain the validated zero-to-two numeric directory levels. File metadata comes
from the pinned read descriptor: UID/GID, permission bits, observed size, mtime/ctime
in nanoseconds, inode and device. Fields unavailable from an injected collector are
null rather than invented. Legacy byte-only test collectors have no filename/metadata.

Observed stat size is distinct from actual bytes read, particularly on pseudo-files.
Metadata describes the collected source, not event time, authenticity, current state
or a match to the selected journal boot. Numeric archive directory names and file
times are not interpreted as crash timestamps. Root cause remains Unknown and boot
identity unverified. Matching hashes are comparison aids, not independent witnesses.

## Lossless content and independent analysis state

Every accepted record contains `content.encoding`, `content.encoding_reason` and
`content.value`. UTF-8 content is retained as text when JSON escaping stays within
a bounded expansion. Non-UTF-8, NUL-containing or expansion-heavy data uses reversible
base64. This changes representation, not bytes or operator visibility; encoding_reason
explains the choice. UTF-8 values re-encode directly to the original bytes, and base64
values decode to the original bytes whose SHA-256 is reported. No content is truncated
or anonymized within an accepted record.

Collection state and signature analysis state are separate. A safely collected binary
or text-structure-limited record remains available for inspection, with analysis
unavailable and no inferred panic signature. Per-record reasons identify non-UTF-8,
NUL content or the text analysis structure limit. Other safely collected records can
still have valid signature observations, giving overall analysis partial. Empty
sources have analysis not_applicable; neither empty content nor unsupported analysis
excludes a crash.

The panic detector still requires supported UTF-8 text without NUL, at most 4096 lines
and at most 4096 characters per line. Signature confidence remains Possible, not a
proven cause or authenticated crash. Binary data is not decompressed or decoded into
new detector formats automatically. Original text can contain untrusted terminal
controls; all rendering uses JSON escaping or base64, never executable terminal text.

## Trust and resource bounds

The source contract is unchanged: supported regular root-owned files, protected
ancestors, pinned no-follow descriptors, nonblocking opens, before/after metadata
checks, at most 64 enumerated entries, eight files, 128 KiB per file and 512 KiB per
source. Archive traversal also retains its two-level/16-directory bounds. Unsafe,
changing, unreadable or over-limit sources still invalidate the entire source
snapshot and discard partial source results. Filesystem calls have no hard deadline.
Unrelated/compressed/reconstructed entries remain counted and excluded rather than
opened; this is a supported-source boundary, not a privacy filter. Fragments are not
reassembled, and custom paths/backends remain outside the collector.

## Verification and remaining scope

Synthetic tests cover source filenames and metadata, archive paths, byte-faithful
text/binary representation, analysis availability, terminal safety and continued
trust/cap/descriptor protections. Integrated acceptance and resource benchmarks
exercise both maximum-sized sources alongside the existing diagnosis workflow.
No live crash, firmware modification, reboot or host evidence fixture is used.

Remaining work includes supported-target qualification, additional crash formats,
stronger provenance, broader source integrations and TUI presentation. These do not
reintroduce privacy-based masking into administrator views. No claim is made that
all host evidence or all possible journal/Atop/pstore fields are collected.
