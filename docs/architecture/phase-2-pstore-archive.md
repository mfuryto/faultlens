# Phase 2: opt-in systemd pstore archive

`faultlens diagnose --pstore-archive` reads supported raw crash records under the
fixed `/var/lib/systemd/pstore` archive. Live `--pstore` and archive collection are
independent opt-ins; either or both can be requested. JSON adds `pstore_archive`
only when requested. Journal, live and archive states are reported independently,
including when the selected journal boot is unavailable. No new package is needed.

## Why inspect the archive?

Systemd-pstore can copy records from live pstore and remove the originals. A live
source alone can therefore miss preserved evidence. This milestone supports flat
raw records, one numeric directory level used by ERST grouping, and two numeric
levels used by EFI grouping. It follows the layouts in systemd v257's implementation,
without interpreting directory names as timestamps, boot IDs or proof of grouping.
Custom archive locations, journal-only storage and other layouts remain unsupported.

## Boundaries and interpretation

The fixed ancestor walk and every numeric subdirectory use pinned, read-only,
O_DIRECTORY/O_NOFOLLOW descriptors. All ancestors and visited directories must be
root-owned without group/world write permissions. No user paths, symlink traversal,
mounts, elevation, file writes, record deletion or archiving operations are accepted.
The traversal is limited to two numeric levels, 16 directories including the archive
root, and 64 total enumerated entries across all levels. Supported raw record files
reuse the live pstore filename allowlist, regular-file/ownership/permission checks,
nonblocking no-follow opens, metadata-change detection and capped reads. The accepted
snapshot is at most eight files, 128 KiB per file and 512 KiB total. Kernel filesystem
calls still have no hard deadline. An unreadable, unsafe, changing, malformed or
oversized supported record, or exceeded traversal limit, invalidates the whole
archive snapshot and discards partial findings. One source failing does not discard
observations from independent sources.

Unknown entries are counted and skipped. Numeric entries are treated as candidate
directories and must pass directory validation. Reconstructed `dmesg.txt`, compressed
records and unknown subtrees are excluded; Faultlens does not parse a reconstructed
copy alongside its raw fragments. Raw fragments are not concatenated or deduplicated.
A signature split across fragments may be missed. Repeated hashes do not establish
independent corroboration, shared boot identity or authenticity.

The existing narrow panic-signature parser reports only record indexes, content
hashes, byte counts and matching line numbers. Raw text, filenames, directory labels
and host details are never emitted. Signature confidence remains Possible, selected
boot association unverified and root cause Unknown. Empty, missing or inaccessible
archives do not exclude a crash. Archive file times and numeric directory names are
not reported as event times. Normalized references can still be sensitive; review
before sharing. No system configuration or permissions are changed.

## Verification and remaining scope

Synthetic tests cover flat, ERST and EFI layouts, skipped reconstructed/compressed
copies, source independence, redaction, absent/denied sources, path validation,
symlink/FIFO/unsafe metadata rejection, partial-result discard and global limits.
The archive benchmark uses eight invented records totaling 512 KiB alongside the
bounded journal. It validates the real parser and CLI with an injected collector;
it does not measure real directory traversal or filesystem latency. The separate
synthetic boundary tests exercise descriptor traversal.

A local ordinary-user smoke test returned a readable archive with no supported
records visible. This verifies graceful handling only, not live crash detection or
archive completeness. Broader supported-host validation, additional signatures,
reassembly and stronger event provenance remain future phase-2 work.

Primary references: [systemd v257 archive implementation](https://github.com/systemd/systemd/blob/v257/src/pstore/pstore.c),
[systemd-pstore service](https://www.freedesktop.org/software/systemd/man/254/systemd-pstore.html).
