# Phase 2: kernel stall detector reports

Diagnose now recognizes three additional narrow kernel-transport report formats:
soft-lockup watchdog notifications, hard-lockup watchdog notifications and blocked-task
notifications. These rules run within the existing selected boot and bounded journal
tail. No new command, package, permission, background collector or configuration is
required. Existing collection limits and source failures remain unchanged.

## Evidence semantics

A matching finding confirms that a supported detector report was recorded. It does
not prove a whole-host freeze, faulty hardware, kernel panic, unexpected shutdown or
root cause. Detector false positives, virtual-machine scheduling effects and detector
configuration are not assessed. Severity is a triage label for the recorded report:
warning for soft lockups/blocked tasks and critical for hard-lockup reports. It is not
an overall health assessment. Missing reports do not exclude stalls; detection may be
disabled, unsupported, suppressed, outside the bounded tail, inaccessible or lost.

Only complete supported message structures match, with optional single trailing
newline. Soft-lockup reports require the watchdog prefix; hard-lockup reports accept
watchdog and NMI-watchdog prefixes; blocked-task reports require the complete INFO
task structure. Generic keywords, application/stdout transport, embedded examples,
trailing text, malformed fields and multiline messages do not match. This is a
versioned-format subset, not a universal detector for all architectures and kernels.
Source formats were checked against Linux v6.12 watchdog/hung-task implementations
and Linux v5.15's NMI watchdog implementation. Kernel/root compromise can still forge
evidence; transport provenance is not cryptographic authentication.

Task names are processed in bounded raw journal memory only and never copied to
findings or output. Name matching is capped at 64 characters and excludes C0/C1
controls. PID and CPU numeric syntax is bounded and range-checked against nonnegative
signed 32-bit values; PID is discarded from findings. Positive soft-lockup durations
must fit unsigned 32-bit seconds; blocked-task durations must fit positive signed
64-bit seconds. Unsupported variants are ignored, not loosely classified.

Findings gain an additive `reported_measurements` object. Existing finding types use
an empty object. New fields are `reported_cpu_index`, `reported_stuck_seconds` and
`reported_blocked_more_than_seconds` where supported by the matching report. CPU
numbers are reported labels, not verified topology. Durations preserve the detector's
claim, including the blocked-task lower-bound wording; they are not independent
measurements, configured thresholds or an inferred total outage duration. The existing
one-matching-record threshold describes evidence count only. No live sysctl defaults
or configuration values are guessed or changed.

All findings retain journal references, static reasoning, limitations and read-only
recommendations. Root cause and shutdown conclusions remain unchanged. Repeated
reports are retained as separate observations, not merged into separate outage counts.
Timeline order uses journal boot-local monotonic report time. Optional Atop pairing
uses report timestamps only, not the entire claimed stall period, and stays Possible.
No stack traces, process names or raw messages are emitted. Pstore readers retain
their existing narrow panic-signature scope; these new rules apply to journal input.

## Verification and remaining scope

Synthetic tests cover supported variants, numeric bounds, application spoofing,
partial/embedded/multiline text, control injection, raw-name redaction, chronological
ordering, repeated reports, the 500-record cap and uncertain Atop pairing. A new
fresh-process benchmark generates 501 invented reports and verifies 500 resulting
findings across all three rules. No crash, lockup, sysctl write or live fault injection
is used in tests or CI. A local read-only smoke examined accessible current-boot
records with no rule matches; this verifies compatibility, not detection accuracy
against a real incident.

This milestone expands evidence-backed diagnostic rules. Broader target-kernel
validation, stack analysis, incident reconstruction and shutdown verification remain
future work; phase 2 is not complete.

Primary references: [Linux v6.12 watchdog source](https://github.com/torvalds/linux/blob/v6.12/kernel/watchdog.c),
[Linux v6.12 hung-task source](https://github.com/torvalds/linux/blob/v6.12/kernel/hung_task.c),
[Linux v5.15 NMI watchdog source](https://github.com/torvalds/linux/blob/v5.15/kernel/watchdog_hld.c),
[kernel detector documentation](https://www.kernel.org/doc/html/v6.12/admin-guide/lockup-watchdogs.html).
