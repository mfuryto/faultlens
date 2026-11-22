# General service troubleshooting

This implements step 1 of the [current delivery plan](../delivery-plan.md). The
1.0.1 reader is already shared across service names; this change adds a coherent
manager-result → concrete message → context → follow-up investigation workflow.
The published 1.0.1 installer remains unchanged until another release is authorized.

## Source and interpretation contract

Use the existing fixed systemctl property query and bounded current-boot unit
journal (201 requested / 200 retained records, two-second and 262144-byte native
limits). No new executable, file reader, elevation, service control or dependency.
Extra requested journal fields describe unit, invocation and job-result metadata.
Original field values remain local administrator data, never executable actions.

Manager result interpretation is independent of message matching and availability.
Explain exit-code, signal/core-dump, timeout, watchdog, OOM kill, start limit,
resource/protocol/condition and unit-load results; keep unfamiliar values and causes
unknown. Show reported main-process exit/signal values. An application's numeric exit
status has application-specific semantics and configured success overrides.

Common message phrases provide conditional investigation guidance across all service
names. AppArmor is an additional specific interpretation. A dependency job report
requires PID 1, systemd/root source metadata and the selected UNIT. Messages with no
supported interpretation remain readable, with error/warning metadata distinguished
from assigned meaning. Repeated messages are not called independent incidents.

## Invocation and chronology

Retain requested unit/invocation metadata by an exact validated journal cursor.
Without a cursor, retain the message but leave extra-field association unverified.
Compare _SYSTEMD_INVOCATION_ID only for the selected _SYSTEMD_UNIT; a manager's own
invocation ID is not the service identity. A supported PID 1/root manager record may
provide INVOCATION_ID with the selected UNIT. Missing/malformed identity stays
unverified. Equal/different reported IDs do not authenticate evidence, verify host
identity or establish a cause. Never hide older or unresolved records.

Current properties and logs are sequential. An active/recovered service can retain
older failures; a failed current state can have inaccessible or incomplete logs.
Context uses up to three retained neighbors on each side, not an exhaustive event
window. Receipt timestamps are not necessarily application event times.

## Navigation

Health → Failed services → selected service loads the inquiry. Messages prioritizes
explained reports, then error/warning metadata, then other retained messages. Every
row opens actual content, explanation or explicit unknown, source scope and next
step. Context and original fields remain accessible. Investigate period selects a
bounded ±2-minute receipt-time window with the current journal-scope preference;
boot remains optional. The button does not assert a service-only or causal query.
Current System/Network requests a new comparison snapshot and explicitly separates
present measurements from the earlier event. Follow-up actions close the modal stack
and preserve references in the retained report until that report is replaced/closed.

## Acceptance

Synthetic web/mail/database/worker/template service names exercise all supported
manager results, unknown results/messages, recovery, same/different/missing invocation
metadata, spoofed job messages, inaccessible/empty/capped sources and invalid time
boundaries. No real operator logs are copied into fixtures and no service is failed
on a host to create a test. Actual Textual tests open arbitrary service messages,
context/originals and period/current-view follow-ups, then verify keyboard navigation,
resize and cancellation. Existing full source, installed-package, resource, policy
and CodeQL gates are required; thresholds and workflow permissions are unchanged.

Primary semantic references: [systemd service results and execution context](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html),
[unit inspection](https://www.freedesktop.org/software/systemd/man/255/systemctl.html)
and [journal fields](https://www.freedesktop.org/software/systemd/man/255/systemd.journal-fields.html).
