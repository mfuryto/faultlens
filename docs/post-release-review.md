# Post-release stabilization review

The owner requested a concrete defect/usability review of published 1.1.0 before
planning further features on 2026-11-22. This review concentrates on the delivered
History / Investigate / Signals / Evidence workflow, service-message navigation,
source availability, installed behavior and existing resource/security contracts.
It is a software review, not a claim that every Linux fault or live SSH scenario
has been independently exercised. Existing operator feedback remains valid.

## Reproduced defects and corrections

| Trigger in 1.1.0 | Observed defect | Corrected behavior |
| --- | --- | --- |
| Native ss output pads its owner column with spaces | A successful command becomes an unavailable owner source | Accept trailing ASCII space/tab padding, retain the original row and preserve byte/row/owner bounds |
| Socket-owner collection fails while all address/route sources succeed | Addresses and routes is incorrectly marked partial | Derive this assessment only from the independent address, IPv4-route and IPv6-route sources |
| Open an unavailable local network source | Its empty view does not explain whether the tool failed or the reader rejected output | Show the source-specific explanation and next step directly, retaining command/reader state in details |
| Pin a service message and highlight it in Evidence | Only the first character appears in the selected-message preview | Show the full retained message with terminal controls escaped and literal markup preserved |
| Open Evidence without a pin, then pin a finding or retained source | Return to source points back to Evidence | Return to the retained inquiry, or the last source section when no inquiry exists |

The owner reported successful address/route commands and a rejected owner source
while using root. A subsequent local check isolated trailing spaces after the ss
owner field; the reported output was within the row and total byte caps. These are
owner observations, not raw evidence copied into fixtures. An invented padded
owner row reproduces the rejection. Tests retain exact originals, reject controls
and unexpected suffixes, and exercise independent address/route coverage and source
explanations in the actual frontend. No broader format or larger cap is assumed.

Three further frontend regression cases fail against the published implementation
before the corrections: complete hostile-message preview, inquiry-origin return,
and last-source return. They inspect the actual rendered workspace, original values
and navigation; return actions do not start another collection. Existing cases
continue to cover already-pinned origins, refreshed/unrelated reports, compact
resize, original records, missing sources and source cancellation.

The corrections change existing parsing and presentation/navigation. They introduce no collector,
dependency, preference key, permission, network operation or evidence persistence.
Development uses 1.1.1.dev0, separately from the immutable published 1.1.0 artifacts.
No new stable release is part of this task.

## Merge verification

Require the full source/frontend regression suite, repository policy, unchanged
performance/constrained-resource checks, Ubuntu/Debian platform checks, both
installed-package lifecycle targets and CodeQL before merge. CI results on the
reviewed PR are the execution receipt; this document does not substitute for them.
Real-server usefulness and new-flow SSH feedback remain operator observations,
not invented passes from the synthetic tests. No production service or network
fault is generated for this review.

## Follow-up

The original four-step delivery sequence is complete. Start the next planning
stage with the [ordered development proposal](next-development-plan.md), preserving
fault investigation as the product goal. New feature implementation follows owner
agreement on that sequence; CVE/whole-host security remains future optional scope.
