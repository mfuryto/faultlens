# Security architecture and threat model

Status: threat model for the planned full local Linux application. Phase 1 implements
bounded read-only collectors, a fixed command catalog and a CLI. The first Phase 2
milestone adds bounded journal normalization and provenance-checked event rules; see
[journal analysis](../architecture/phase-2-journal.md). The optional
[Atop adapter](../architecture/phase-2-atop.md) adds protected-descriptor replay,
child-only native resource limits and uncertain wall-time pairing. See
[Phase 1 decisions](../architecture/phase-1.md) for implemented boundaries and tests.
The [coverage and pstore milestone](../architecture/phase-2-coverage-pstore.md) adds
uncertain gap assessments and opt-in descriptor-bounded live crash-signature reading.
The [archive reader](../architecture/phase-2-pstore-archive.md) extends this to fixed,
protected systemd archive paths with global traversal bounds.
Pstore content is treated as untrusted and exposed locally through escaped/lossless
administrator views. Signature references do not authenticate evidence or associate a boot. No record deletion or permission changes occur.
[Kernel stall report rules](../architecture/phase-2-stall-rules.md) require full supported
message formats and kernel transport, omit task identities, and distinguish detector
observations from root-cause attribution.
[Retained journal chronology](../architecture/phase-2-reconstruction.md) describes
receipt-time positions and bounded clock-mapping examples without causal links or
inferences from silent intervals. It reuses already normalized evidence only.
[Explicit journal scope](../architecture/phase-2-journal-scope.md) keeps boot listing
and selected-boot collection consistent, never falls back across scopes, and reports
provenance counts without granting rights or inferring complete access.
[Targeted candidate search](../architecture/phase-2-targeted-search.md) uses two fixed
field/priority profiles with per-query resource limits and validates all returned
candidates before trimming. It never accepts user regex or path filters and keeps
filtered chronology separate from ordinary tail coverage and causal claims.
[Unclassified candidate review](../architecture/phase-2-candidate-review.md) emits only
fixed explanations and bounded normalized metadata. It never labels unknown messages
benign or associates rule matches solely through potentially identical references.
The [OverlayFS reuse rule](../architecture/phase-2-overlayfs-rule.md) matches only
complete kernel warning formats, distinguishes historical evidence from current
mount state and never triggers mount/service operations or protection changes.
[Exact boot-ID selection](../architecture/phase-2-boot-selection.md) requires validated
format and membership in the bounded requested-scope listing. It never uses an absent
ID to bypass scope or substitutes another boot.
[Historical receipt boundaries](../architecture/phase-2-journal-window.md) accept only
bounded integer timestamps, construct fixed native arguments and revalidate all
returned records against both inclusive requested boundaries before trimming.
Reversed ranges fail before collection; failed queries never retry a broader range.
[Journal-loss rules](../architecture/phase-2-journal-loss.md) require internal driver
transport and exact structured IDs; copied application text/IDs do not suffice.
They emit no raw text or unit names and never adjust logging policy.
[Historical CPU accounting](../architecture/phase-2-atop-cpu.md) uses already
validated aggregate counters without expanding collection. Unknown/RESET totals stay
null, negative inputs fail closed, and interval shares never upgrade causal confidence.
[Multi-boot summaries](../architecture/phase-2-overview.md) reuse one scope-specific
listing snapshot, query only selected immutable IDs and cap selection at seven.
Per-boot failures remain visible without replacement or automatic optional-source replay.
[Extended Atop replay](../architecture/phase-2-atop-extended.md) requires a separate
explicit flag and fixed label profile. Process names/PIDs/wait channels and device/
interface names are available to local administrators, with reported hostnames and
source replay lines. Fingerprints do not verify identity. Record pairing and cardinality
limits fail closed before resource results are emitted.
[Phase 3 network sampling](../architecture/phase-3-network.md) reads only fixed
namespace counter sources, validates paired columns and unique interface labels, and
uses measured monotonic durations. Source failures remain independent; counter growth
never establishes an attack. No endpoints, packet capture, remote probe or policy write
is introduced.
Private evidence storage, full incident reconstruction, TUI and mutation boundaries remain design
requirements, not claims of completed implementation.

## Scope, assets, and trust boundaries

Protect host integrity and availability, credentials and personal information in
logs, private network topology, evidence integrity, and the accuracy of findings.
Assume logs and command output may contain attacker-controlled text. Assume ordinary
users may control paths, environment variables, terminal dimensions, and input files.
A compromised kernel or root user can falsify local evidence and is outside the
integrity guarantees; acknowledge this limitation rather than asserting authenticity.

Planned flow:

```text
local OS interfaces -> bounded collectors -> normalized evidence -> diagnostic rules
                                               |                       |
                                      local private storage      CLI/TUI renderer
user-approved configuration plan -> separate narrow mutation boundary
```

Collectors prefer `/proc`, `/sys`, journald, `systemctl`, `ss`, `ip`, and `nstat`.
Optional `atop`, sysstat, pstore, nftables, and sosreport integrations must declare
availability, privilege and data sensitivity. No custom daemon, database, cloud
collector, or external service is justified by the current scope. CLI behavior
must work without the proposed prompt_toolkit TUI dependency.

## Threats and required controls

| Threat / boundary | Required control | Future verification |
| --- | --- | --- |
| Shell or argument injection through filters, unit names, paths | Trusted absolute executable allowlist, structured argv, option validation and `--` where supported; no shell, implicit sudo, pager or user PATH resolution | Malicious arguments, hostile PATH/environment and missing executable tests |
| Malicious logs exploit parsers or terminals | Size/depth/time limits, strict decoding policy, escape terminal control sequences including OSC hyperlinks and clipboard sequences | Escape injection, malformed encoding, oversized and truncated evidence tests |
| Elevated collection changes the host | Unprivileged read-only defaults; capability-specific access checks; no automatic elevation | Denied-permission and no-write integration tests |
| Configuration changes break remote access or logging | Separate optional mutation interface, exact preview, explicit confirmation, validation, backup and rollback; reject unattended changes by default | Confirmation cancellation, partial failure, rollback tests |
| Evidence export leaks secrets or topology | Local-only storage, 0700/0600, restrictive umask, atomic exclusive creation, reject symlinks and path traversal, operator-selected filtering, explicit export destination and retention | Permissions, symlink races, traversal, redaction and retention tests |
| Resource exhaustion worsens an incident | Bounded command duration/output, cancellation, sampling budgets, no default packet capture or background polling | Measured CPU/RAM/I/O budgets and timeout tests on small VPS systems |
| Incorrect attribution or missing history misleads operators | Preserve source/time/boot context; separate observed events and hypotheses; expose confidence, thresholds, gaps and clock uncertainty | Deterministic rule tests and ambiguous/missing-history cases |
| Dependencies or CI introduce supply-chain compromise | Minimal dependencies, verified source and license review, future hash-locked installs; pinned actions, read-only baseline token, job-scoped CodeQL findings upload, no application secrets or diagnostic artifact uploads | Baseline checks, dependency review, owner review |

## Evidence semantics and limitations

Use Confirmed, Probable, Possible, or Unknown with explicit supporting evidence.
Do not infer a confirmed attack from traffic volume alone. Do not label an unexpected
reboot a confirmed kernel panic without relevant evidence. Disk writes may stop
before a freeze; persistent journald, atop, and pstore may be unavailable, rotated,
incomplete, or altered. Local timestamps can shift. Report collection errors and
missing observations without inventing past measurements.

Keep raw evidence separate from summaries; preserve provenance and transformations.
Hashes can detect later changes but cannot prove that a compromised host was truthful.
Retention must be explicit and configurable. Deletion on SSDs or snapshots is not
guaranteed secure erasure. Do not emit raw sensitive data into application debug logs.

## Architecture decisions and open work

Prefer existing tools rather than duplicating collectors. Evaluate their actual
interfaces and supported Debian/Ubuntu versions before implementation. Optional
integration failures must not disable unrelated diagnostics. Record dependency
and license decisions before adding packages. Apply relevant OWASP ASVS 5.0 Level 2
principles to local input validation, secrets, permissions and integrity; no ASVS
certification or web-application compliance is claimed.

Target memory below 50 MB where practical and minimal CPU; initial synthetic CLI
measurements are recorded in [benchmarks](../benchmarks.md). Production VPS performance
and full TUI memory usage have not yet been verified.
Measure polling and retention overhead before choosing the proposed atop 30-second
interval. Define measurable latency, timeout and evidence-size budgets alongside the
first collectors. No security baseline here substitutes for runtime security tests.

## Local administrator visibility

Faultlens is an administrator tool, not a privacy filter. Relevant identities and
original evidence must be available locally under existing Linux permissions.
`diagnose --search-ssh` includes parsed usernames/peers/ports and all retained SSH
candidate messages; `--show-evidence` exposes retained ordinary/filtered journal
messages and original cursors. Output uses JSON escaping so hostile controls cannot
operate the terminal, while decoded JSON preserves the original values. Original
MESSAGE values remain available even when they are unsupported for text analysis.
Malformed/oversized input and excessive JSON nesting are explicit source failures,
not privacy redactions. No automatic save, upload or privilege escalation is added.

Earlier milestone identity omissions describe implemented summary/adapter limits,
not requirements to conceal information from administrators. Full identity/evidence
views are implemented for retained journal/SSH, Atop and pstore content. Both Atop
profiles expose recorded hostnames/source lines; pstore exposes source paths, observed
metadata and lossless content. Future TUI integration and uncollected source fields
remain separate work. Local visibility
must not be confused with permission to publish host evidence in repository files,
CI artifacts or vulnerability reports. Tests continue to use synthetic data only.
