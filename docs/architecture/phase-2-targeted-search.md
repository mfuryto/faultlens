# Phase 2: targeted event candidates beyond the journal tail

An ordinary 500-record tail may span only seconds on a noisy host. The explicit
`diagnose --search-events` option adds two fixed candidate queries over the accessible
selected boot, allowing older supported reports to be found without collecting its
entire unfiltered history. No arbitrary regex, path, host, time string or user-provided
journal match is accepted. No new package, privilege or system change is introduced.

```sh
./bin/faultlens history --system-journal
./bin/faultlens diagnose --boot 0 --system-journal --search-events --json
./bin/faultlens diagnose --previous-boot --search-events
```

Use the same journal scope when selecting boot indices. Default visible scope still
means accessible journals only and may lack system evidence. System scope grants no
access and does not elevate. Tests, Git and ordinary development still run as the
checkout owner; journal access is a separate host policy decision.

## Fixed selection and bounds

After resolving the requested index to an immutable boot ID, two queries use that
same ID and scope, with no alternate-boot/scope retry:

- `kernel_warnings`: kernel transport and priorities 0 through 4 (warning or more
  severe), using native journal field/priority selection.
- `systemd_events`: trusted PID 1/systemd metadata and either of the existing
  supported unit-start-job-failure or shutdown-marker message IDs. Repeated matches
  for the same MESSAGE_ID field are alternatives; PID and comm constraints both apply.

Each query asks for at most 501 candidates, retaining at most 500 using the existing
sentinel policy. Native fixed filters reduce ordinary informational noise before the
record cap. Other kernel warnings can still consume the cap, and lower-priority kernel
reports are excluded even if their text resembles a supported rule. The search does
not claim to find every relevant event. There is no dependency on PCRE support and
no message grep whose no-match exit code could be confused with collection failure.

Both queries inherit the trusted executable catalog, fixed minimal environment,
no shell/stdin/pager, two-second subprocess deadline and 256 KiB combined output cap.
Priority metadata, candidate provenance and selected-boot identity are validated for
all returned records, including the sentinel before trimming. Unexpected provenance,
malformed/oversized output, command failure or timeout discards that query's partial
results. The other query and ordinary tail remain independent. No whole-boot raw
report is retained or saved. Each command has its own deadline and bounded cleanup;
these are not a hard whole-CLI deadline or an I/O/memory guarantee for native
journalctl/kernel internals. The selected boot may be large and actual native search
cost depends on journal files and indexing.

## Results and interpretation

JSON adds `event_search` only when requested. It reports scope, immutable boot ID,
unknown completeness and per-query command/parse states, retained candidate count,
cap flag, unsupported-message count, filtered candidate window, supported findings
and monotonic timeline. A complete empty response is an available query, not proof
of absent events, complete access or a healthy host. Search state is available when
both queries complete and parse safely, partial when one does, and unavailable when
neither does or boot scope cannot be resolved. A failed initial listing or missing
selected boot triggers no search. A tail failure does not discard completed searches.

Raw messages, priority text, process metadata and unhashed cursors are not emitted.
Findings use the existing evidence-backed rules and normalized references. Supported
signature matches remain recorded reports, not causes. Candidate first/last times
and offsets describe filtered journal receipt records only, never full-boot coverage,
incident boundaries, missing-log gaps or outage duration. Unsupported message content
remains explicit and unclassified. Numeric priority fields are checked against the
single-digit 0–7 range; kernel candidates must actually carry priority 0–4.

Search results are intentionally separate from top-level tail findings, source counters, reconstruction,
shutdown assessment and Atop pairing. They may repeat the tail or one another and
are not independent corroboration or distinct incident counts. Pstore still reports
separately. No extra Atop replay is performed for older search hits, and no cross-source
cause or boot identity is inferred. Inspect `event_search.queries[*].findings` for
older matches even when top-level findings are empty or the main tail is unavailable.
Overall rendered-report exit codes retain their existing semantics; zero does not
assert every source succeeded. The text renderer shows query states, counts, caps,
filtered candidate spans, evidence, reasoning and limitations without raw payloads.

## Verification and remaining work

Synthetic tests cover older events outside the tail, independent failures, empty
responses, no boot/scope fallback, both systemd IDs, candidate revalidation including
the omitted sentinel, per-query caps, reverse responses, unclassified warnings,
redaction, duplicate views and unchanged Atop scope. The new benchmark includes two
maximum-size candidate result sets plus the maximum ordinary tail. No live incident
fixtures or privileged tests are used in CI.

A read-only local visible-scope smoke completed both queries with no candidates.
This verifies native argument compatibility and empty-response handling, not complete
system access or real incident-detection accuracy. The ordinary user previously lacked
system-journal access; successful native system-scope searches on the owner's root
session remain a separate manual compatibility test. Broader time selection, candidate
pagination, lower-priority supported events and targeted resource correlation remain
future work. Phase 2 and shutdown verification are not complete.

Primary reference: [journalctl priority, field matching and record limits](https://www.freedesktop.org/software/systemd/man/253/journalctl.html).
