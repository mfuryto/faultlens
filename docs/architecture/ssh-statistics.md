# SSH authentication statistics

Approved network-sequence step 1. Network offers an explicit SSH authentication
history action with Since boot, Last hour, Last day and a timezone-qualified Period.
`faultlens ssh` exposes the same collector; JSON, readable details and original
evidence remain available. Opening Network alone does not read SSH history.

## Scope and counting

Since boot reads the immutable current kernel boot identity from the fixed
`/proc/sys/kernel/random/boot_id`, not the newest visible journal listing. CLI can
explicitly select another immutable boot ID. Hour/day/period queries otherwise span
accessible boots. The end boundary is frozen when collection starts. Existing
system/visible journal selection grants no extra permission. UI scope uses Settings;
the SSH window does not silently inherit the separate inquiry's boot filter.

Supported root-UID/syslog producer names are sshd, sshd-session and sshd-auth.
Classify complete Failed, Accepted and Partial messages for password, publickey,
keyboard-interactive[/pam], hostbased and gssapi-with-mic. Retain unknown formats,
binary/unsupported messages and methods as unclassified. Invalid-user messages are
counted as context separately; PAM context is not a second failed authentication.
Count explicit reports, not distinct connections or attackers. Distinct journal
records can still duplicate application events. Partial MFA and accepted methods
do not establish a complete authorized session or compromise.

Aggregate per reported username, normalized numeric peer and receipt-time bucket,
including outcome counts, reported methods, first/last receipt times and direct
original-record indices. Hour/period <= one hour uses minute buckets; longer windows
use hours. Only observed buckets appear; omitted empty buckets are not proof of
continuous collection. Cross-boot monotonic times are not compared. Original values,
messages and cursors remain available without masking, with literal terminal escaping.

## Bounded forward reading

The new dedicated reader uses `journalctl --lines=+200`, fixed producer filters,
explicit scope/end and `--after-cursor` for subsequent pages. It never follows the
journal, writes cursor files or runs a shell. Existing 500-candidate investigation
queries remain unchanged. Validate a full page before using it, requiring unique
cursors and valid producer, boot and receipt bounds. Duplicate/repeated cursors
stop the scan; no guessed continuation or fallback source is used.

Bounds: 200 rows/256 KiB per capture, two seconds per native call, 50 pages, 20 seconds
checked between calls, 2 MiB of serialized original evidence and 512 groups in each
table. The last native call can extend past the between-call deadline by at most its
two-second capture timeout, excluding local parsing/scheduling. Stop before counting
a record whose evidence/group would exceed a bound. Retain every counted original;
do not claim an aggregate without its retained evidence. The complete UI report is
also subject to the existing 8 MiB capture bound. Source cancellation terminates
native subprocess groups through the existing collection boundary.

`exhausted` describes the end of the currently accessible filtered query, not complete
logging since boot. Retention, rate limits, clock changes, rotation during pagination,
other transports/namespaces and forged local evidence remain unverified. A bounded,
failed or invalid continuation yields an explicit lower bound, not a full-period
total. An unavailable source has null totals; readable zero reports is separate.

## Interface and acceptance

The modal is cancellable and supports window changes, refresh, group/record/original
navigation and Evidence pinning. One SSH report is cached in memory with its original
scope; refreshing releases that cache before reading, and failure never restores it
as a new successful result. Pinned Evidence can retain an older report explicitly.
No report/window is persisted to preferences or disk and no Fail2ban query, ban,
firewall read/change, external scan or new dependency is added in this step.

Synthetic tests cover pagination beyond 500, mixed boot periods, actual kernel-boot
selection, outcomes/context, hostile messages, empty/missing/invalid/duplicate pages,
caps and native argument validation. Real frontend tests cover windows, groups,
records, original fields, pins, compact resize, failed refresh and cancellation.
Two 2,000-record CLI/frontend scenarios extend existing performance and constrained
profiles with unchanged CPU/wall/RSS limits. Native platform and installed-package
qualification include the eighth `ssh` CLI contract.

Primary references: [journalctl forward lines/cursors](https://www.freedesktop.org/software/systemd/man/256/journalctl.html),
[OpenSSH authentication logging](https://github.com/openssh/openssh-portable/blob/master/auth.c),
[OpenSSH logging configuration](https://man.openbsd.org/sshd_config#LogLevel).
