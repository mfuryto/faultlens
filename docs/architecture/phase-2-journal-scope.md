# Phase 2: explicit journal source scope

A readable journal tail may contain no kernel or system-manager evidence. A small
record count alone cannot establish permissions, disabled logging or system health.
This milestone makes source selection and collection status explicit without changing
access rights, installing tools or probing broader sources automatically.

## Commands and scope consistency

The default remains `visible`: journalctl's accessible default set, potentially
including user and system journals depending on existing access. It is not a claim
that kernel or system-service logs were examined. To explicitly select accessible
system-service/kernel journals, use:

```sh
./bin/faultlens history --system-journal
./bin/faultlens diagnose --boot 0 --system-journal --json
```

The flag is valid only for history and diagnose. Both the boot listing and selected
boot collection receive the fixed `--system` source option. Boot indices can differ
between scopes; consult history with the same flag before choosing an index. The
index is still resolved to an immutable boot ID before querying. If listing,
selection, collection or parsing fails, there is no retry in visible scope and no
fallback to a different boot. Existing visible-mode calls remain unchanged.

`--system-journal` selects sources, not privileges. It does not bypass ACLs, unlock
journals, inspect arbitrary paths or enable recording. No sudo, group modification,
permission change or service operation is performed. Broader access is a separate
administrator decision subject to the host's journal-access policy, not a package
installation request. Even successful system-scope collection can be partial.
The existing `check` and preservation assessment retain visible boot-listing scope.

## Report semantics

History and diagnose gain an additive `journal_scope` object with requested scope
and completeness fixed to unknown. Diagnose counts retained kernel-transport
records and records with trusted PID 1/systemd metadata. These counts include
records whose message content is unclassifiable, because they describe provenance,
not recognized events. `system_evidence_observed` is true when either count is
positive, false when neither was seen, and null before successful collection/parsing.
History lists metadata only and leaves these counters null. No match in the retained
tail does not prove absent system access; a positive count does not prove complete
system history or source authenticity against root/kernel compromise.

Diagnose also gains `journal_collection` with safe command state, return code and
parse state (`not_attempted`, `valid`, `empty` or `invalid`). It is null when selected-
boot collection never ran. Failed command output is never parsed as evidence.
Raw stdout/stderr, journalctl permission hints and other untrusted text are not copied
into the report. A nonzero tool exit status does not by itself establish access denial,
missing journals or a missing boot. The text renderer shows source scope, observed
system-evidence counts and failed/empty/invalid collection status where relevant.

Existing report exit codes remain unchanged: a rendered partial/unavailable report
can exit zero. Inspect state, boot_listing and journal_collection fields. The fixed
trusted executable catalog, minimal environment, no shell/stdin, two-second deadline,
256 KiB output limit, selected boot validation and 500-record retention cap apply to
both scopes. Findings, root causes, shutdown uncertainty and chronology retain their
existing semantics. Optional Atop and pstore behavior remains unchanged; pstore can
still report independently when journal selection fails.

## Verification and remaining work

Synthetic tests cover default behavior, scope-consistent index resolution, fixed
arguments, no fallback on failed/empty/invalid listing or collection, safe failure
status, source counts, CLI validation, partial-access uncertainty, output redaction
and independent pstore reporting. The system-mode benchmark uses invented source
results and verifies 500 retained kernel records without claiming completeness.
No real diagnostic fixtures or privileged tests are included in CI.

A read-only local smoke found 37 visible records with no kernel/PID 1 systemd
records, while the system-scope listing exited nonzero and did not trigger collection
or fallback. This verifies honest partial-source reporting, not access-denial cause
or successful native system-scope analysis on a fully readable host. Broader target-
host/ACL validation, richer source capability assessment and shutdown verification
remain future work.

Primary reference: [journalctl source selection and access](https://www.freedesktop.org/software/systemd/man/253/journalctl.html).
