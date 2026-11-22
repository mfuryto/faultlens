# Current process and filesystem investigation

System answers two current questions: which retained processes are using CPU or
resident memory, and which sampled filesystem has little ordinary-user space or
few available inodes. Health uses the same sources. These measurements never
explain an earlier incident by themselves and never control a process or repair
storage. General network/attack investigation remains the next delivery step.

## Process evidence

A separate isolated Python worker opens fixed procfs sources, takes two samples
and compares PID plus reported start ticks. At most 32,768 directory entries are
enumerated and the lowest 512 visible PIDs are retained per sample. This selection
is deterministic, not a guarantee of finding the busiest process on a larger host.
The table ranks retained comparable CPU values, then RSS. Every retained row and
its exact counters remain accessible through details/originals and CLI JSON.

CPU uses each process's observation interval and the kernel clock-tick unit. It
is relative to one logical CPU, so multithreaded work can exceed 100%. Exited,
new/reused, unreadable or regressed process identities do not acquire a guessed
zero. Short samples have tick-resolution and scheduling limits. Reads are sequential;
a name, state, RSS and cgroup are not an atomic snapshot. RSS is approximate resident
memory including shared pages, not unique/private memory, PSS or a service limit.
Kernel names may be truncated. No command lines, environments or descriptor targets
are collected.

The reported systemd cgroup path may supply a validated system-service association.
Only the unified hierarchy or the named systemd hierarchy under `/system.slice`
is interpreted; user-service paths are not promoted to system units. This association
opens the existing general service reader with existing access. It does not prove
service identity, current membership or causality. Raw cgroup data and unavailable
association state remain available.

Procfs files are opened relative to directory descriptors without following source
symlinks. Bounded strict decoding, numeric ranges and PID identity checks reject
unsupported records. Missing, denied, malformed and other read failures are counted
separately. A process/enumeration cap and association failures make coverage partial.
Current PID namespace, procfs visibility and caller access constrain the result.

## Filesystem evidence

The fixed `/proc/self/mountinfo` inventory is bounded to 1 MiB and 8,192 parsed
entries. It retains at most 256 mount rows, preferring `/`, `/var`, `/home`, `/srv`,
`/tmp`, `/run` and `/boot`, then shallow paths. Up to 32 local capacity probes run.
The inventory is per current mount namespace. A descriptive filesystem-root label
is retained as metadata and never used as an input path.

The initial probe allowlist is ext2/3/4, XFS, Btrfs, F2FS, tmpfs, OverlayFS,
SquashFS, EROFS and ZFS. Remote, FUSE, autofs and other types remain listed without
capacity probes. An unsupported ancestor also excludes a local-looking child.
These exclusions are coverage limits, not findings of failure or health.

Each probe walks the reported absolute mount target through directory descriptors
without following symlinks, then checks device and kernel mount ID on the opened
descriptor before `fstatvfs`. Regular-file bind mounts are supported. A hidden,
changed or inaccessible identity stays unavailable. The full table includes these
rows and explains exclusions. Mount ID checks constrain races; they cannot establish
snapshot atomicity, kernel authenticity or complete topology under mount changes.

Capacity and inode counters are validated independently. Ordinary-user space usage
uses `used / (used + available)`; inode usage uses the analogous available-inode
counts. Review is at 90%, critical at 95%, based on exact integer ratios before
display rounding. A missing inode denominator is unassessed. Read-only mounts are
informational, including intentionally full read-only images. A reported read-only
root also suppresses the older writable-root pressure assessment. This is not a
claim that unexpected read-only state is harmless: inspect the intended policy
and retained errors when relevant.

Do not add mount capacities or RSS across rows as unique resources. Bind/shared
storage, containers, reserved capacity, permissions and quotas affect interpretation.
No block contents, directory-size traversal, SMART probe, repair or cleanup runs.
Capacity does not establish integrity, hardware health, throughput or past pressure.

## Execution and output boundary

Processes and filesystems use independent workers, each with the existing parent
capture deadline of two seconds and a 1 MiB response cap. The process sample interval
is the existing validated 0.05–1 second setting. Each worker uses isolated stdlib
Python (`-I -B -S`), no-new-privileges, 128 MiB address space, one CPU second,
64 descriptors, disabled core dumps and a zero regular-file write-size limit.
No new dependencies or native tools are installed. The packaged private module
allowlist includes the workers; they do not rely on a checkout or global frontend.

The parent validates finite values, identity uniqueness, schema, ranges and metric
arithmetic. Invalid, timed-out or excessive output makes only that source
unavailable. Collection start/end timestamps are retained; the enclosing report
completion time follows collection. Existing UI worker cancellation remains in use.
Kernel-uninterruptible filesystem I/O cannot be given a guaranteed hard deadline by
a userspace timeout; local probe restrictions reduce exposure, not that OS limit.

Source strings render literally with reversible escaping. Administrator evidence is
not privacy-masked or persisted. Grouped rows explain coverage; full retained tables,
originals and CLI details remain accessible. No unavailable source becomes a healthy
zero or an assertion that the host has no faults.

## Verification and references

Invented fixtures cover process tick calculations, PID reuse/reset, missing access,
symlink rejection, cgroup ambiguity, independent full filesystems/inodes, exact
threshold boundaries, read-only images, missing inode counts, remote/unsafe
ancestors, mount identity changes, caps and independent worker failures. Textual
checks cover source/detail/original/service navigation, compact resize and unavailable
sources. Existing status and TUI-status resource scenarios now exercise 512 process
and 256 mount rows without changing CPU, memory or wall-time budgets. Native source
and installed Debian/Ubuntu qualification verify both source contracts, including
legitimate unavailable/partial outcomes; they do not manufacture host failures.

Primary semantics: [kernel procfs documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html),
[process stat fields](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html),
[mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html),
[statvfs](https://man7.org/linux/man-pages/man2/statvfs.2.html) and
[descriptor opening](https://man7.org/linux/man-pages/man2/open.2.html).
