# Security architecture and threat model

Status: threat model for the planned full local Linux application. Phase 1 implements
bounded read-only collectors, a fixed command catalog and a CLI. The first Phase 2
milestone adds bounded journal normalization and provenance-checked event rules; see
[journal analysis](../architecture/phase-2-journal.md). See
[Phase 1 decisions](../architecture/phase-1.md) for implemented boundaries and tests.
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
| Evidence export leaks secrets or topology | Local-only storage, 0700/0600, restrictive umask, atomic exclusive creation, reject symlinks and path traversal, redaction preview, explicit export destination and retention | Permissions, symlink races, traversal, redaction and retention tests |
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
