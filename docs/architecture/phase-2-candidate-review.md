# Phase 2: explain unclassified targeted candidates

`diagnose --search-events` now explains the retained candidates that do not produce
a supported finding. No new flag, query, permission or dependency is required.
Selection, limits, source scope and native commands remain unchanged. This is a
review aid for unknown evidence, not a new message classifier or root-cause rule.

## Counts and reasons

Each successful targeted query gains `candidate_review`. It counts retained
candidates, candidates matched by at least one supported rule, unclassified
candidates, unavailable message content and recorded priorities. Matched-candidate
counts describe records, not the number of findings or independent incidents.
Priorities are source metadata with fixed standard labels; an error or emergency
label does not independently confirm severity, health, authenticity or cause.

Unclassified candidates have one of two fixed explanations:

- `no_supported_signature`: supported per-record rules did not match the candidate.
  This does not mean the report is harmless or irrelevant.
- `unsupported_message_content`: content was missing, binary or oversized, so a
  supported text signature could not be evaluated.

Structured systemd IDs can still match when text content is unavailable. Such a
record counts as matched and as having unavailable content; it is not incorrectly
classified as an unsupported text finding. Unavailable-content counts in this review
cover retained records only, while the existing response-level unsupported-message
count may also include the omitted 501st sentinel. Failed, malformed or unsafe
queries have a null review, not successful zero counts. A safely parsed empty query
has an available empty review without implying complete access or a healthy system.

## Bounded metadata examples

Counts cover all retained candidates, but only the newest 20 unclassified examples
in normalized monotonic receipt order are shown. Each has a collection-local
candidate index, normalized evidence reference, recorded priority/label, fixed
selection reason, fixed non-match explanation and Unknown classification/cause
confidence. Equal-timestamp ties preserve the existing input order without claiming
independent chronological order. An explicit truncation flag describes the example
limit separately from the candidate collection cap. The sample is the newest subset,
not a random or representative sample of all warnings.

Task names, hostnames, raw messages and message-content fingerprints are not included.
References retain only the existing boot/time metadata and optional cursor hash.
These normalized references can still be sensitive. Candidate indices can change
between collections; they are not durable IDs. Cursor hashes cannot be passed to
journalctl as real cursors. References without a cursor can be identical for distinct
records with equal timestamps; the implementation associates rule matches by retained
record position, never by reference equality. This prevents an unknown record from
being mislabeled as matched because it shares metadata with another record.

The text renderer shows counts, priority distribution, bounded example references,
selection reasons, explanations and local-review guidance. No raw journal viewer is
launched, and nothing is exported or uploaded. A trusted local viewer may be used
separately to inspect evidence before assigning meaning. This milestone does not
provide raw-entry lookup or semantic explanations for unsupported message formats.
Existing supported findings, main-tail coverage, Atop pairing, pstore behavior,
shutdown uncertainty and root-cause conclusions remain unchanged.

## Verification and remaining scope

Synthetic tests cover mixed matched/unknown/unavailable records, all retained priority
counts, newest-example bounds, cap vs example truncation, structured IDs with binary
content, response vs retained counts, identical references without cursors, normalized
ordering, failed/empty queries and raw-field/control redaction in text and JSON.
The additional benchmark exercises 500 unknown kernel candidates, 20 example slots
and explicit truncation alongside the ordinary tail and structured query. No real
journal fixtures, crash injection or privilege changes are used in CI.

A local read-only visible-scope smoke verified successful empty reviews. Previously
supplied owner-run system-scope output showed 16 unclassified kernel candidates;
this motivated the metadata explanation, but their raw content was not collected
for implementation or validation. New explanation behavior on those live candidates
remains a manual owner-run check. Broader semantic rules, explicit local lookup and
further supported-host validation remain future phase-2 work.
