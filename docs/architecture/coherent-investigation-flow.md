# Coherent investigation and evidence flow

This completes delivery-plan step 4. History opens retained report examples,
Investigate owns the chosen question/time/source scope, Signals reviews that inquiry,
and Evidence retains an explicitly selected source/finding/record. Boot identity
remains optional where the query permits. CLI `security` remains a compatible
current-counter command; the terminal Signals section has a distinct inquiry role.

## History and inquiry context

History shows retained report examples alongside explicit boot-source rows. Each
example keeps its own receipt time, immutable boot identity, source reference and
one linked original record where that reference resolves. The source overview
retains up to three examples per selected boot, within the existing seven-boot,
500-record/native-byte caps. Missing/ambiguous links never acquire a guessed message.
The existing source/boot rows expose bounded-tail, empty, unavailable and unexamined
states. This is an event-oriented entry to retained evidence, not complete history.

Open an example to read its actual message or investigate two minutes around the
receipt timestamp. Timestamp ranges are clamped to supported bounds; unknown times
do not become guessed periods. This action clears the optional boot filter so a
period can span accessible boots. Investigate this boot remains a separate explicit
action. Wall-clock times can regress; monotonic values from different boots are
never combined into causal chronology.

An inquiry origin retains the selected report, service message or reported peer.
It is navigation context, not an implicit service/peer filter. Actual query bounds,
journal scope and optional boot filters remain separately visible. Existing related
service readers and network/record sources remain available with their own limits.
Selecting a new standalone inquiry releases the previous origin; follow-up actions
explicitly retain the relevant origin. No subject grants access or changes a server.

Journal partitions carry small `inquiry_context` metadata: mode, requested window,
requested/resolved optional boot filter, journal scope and source role. A partition's
boot identity is not silently promoted to a query filter. Current measurement
snapshots identify their associated journal inquiry separately from measurement
collection time. This metadata is additive in JSON and never changes source evidence
or establishes temporal causality.

## Signals

Signals reuses the selected retained inquiry. If none exists, opening the section
loads the configured inquiry through the same cancellable source job as Investigate.
It never starts a separate current-network scan. Refresh explicitly refreshes that
inquiry; failure/cancellation does not fall back to an unrelated Network snapshot.
Settings changes remain visible as stale query options instead of relabeling old
data as if newly collected. Opening Investigate from Signals keeps the exact report.

The table prioritizes journal findings, unclassified warning records, current
operational review items and source gaps. Matching rule/reference previews from
multiple queries are consolidated only when all journal cursor hashes and boot/time
references agree. This is presentation consolidation, not independent corroboration;
original query results remain accessible in Investigate/Evidence. No cursor means
no inferred duplicate identity. Current network cards supply actual review observations
without duplicating their overview/pressure summary rows. Peer expectation cards
remain informational; no comprehensive security/attack verdict is added.

An unavailable inquiry says signals could not be assessed. Readable no-match,
readable empty, unrequested and capped sources remain distinct. The preview is
bounded to 128 rows; a visible limit row points to the complete retained inquiry.
Observation counts are not distinct incidents. Root cause and attack assessment
remain unverified.

## Evidence selection

Press `v` or choose Evidence from a finding, source, service or original-record
dialog to retain that exact selection with its owning report. Evidence shows the
selected subject, original scope/time, direct explanation/record navigation, complete
original fields, Return to source and Use current inquiry instead. Related reports
and original fields remain explicit secondary views, not a primary JSON menu.

A pinned selection does not follow the most recently inserted cache entry. Visits
to another tab, preference changes and source refreshes do not replace it. Its
original collection time is visible. Use current inquiry explicitly replaces the
pin; Return to source explains that a refreshed source may now contain different
data. Without a pin, Evidence follows the retained inquiry, or the explicitly last
visited source when no inquiry exists. Evidence never collects.

State is bounded to one selected evidence report and one inquiry origin, held by
reference with existing source snapshots. There are no deep evidence copies or
selection history. Replacing a selection/origin drops that reference. This can keep
one older bounded report alive across refresh; it cannot accumulate an unbounded
history. No diagnostic evidence or navigation subject is written to preferences,
disk, a database or external service. Existing original escaping/privacy behavior
is preserved: administrator fields remain available without masking.

## Settings and compatibility

Settings explain collection purpose, required existing access and the last retained
source state. Availability text uses cached metadata only, never another probe.
An enabled option does not prove readable logs or a working recorder. The existing
preference schema/keys remain unchanged, so saved preferences continue to load.
Only user preferences persist; contexts and evidence selections are session-only.

The combined additive feature work originally used 1.1.0.dev0 after stable 1.0.1;
no 1.0.2 release was published. The owner subsequently authorized 1.1.0 publication,
completed on 2026-11-22. Post-release development uses 1.1.1.dev0. Existing release
assets/tags and stable install instructions remain intact.

## Verification

Invented fixtures cover cross-boot sources, immutable report/record identity,
ambiguous links, unknown/out-of-range times, readable empty/unavailable/capped
queries, consolidated duplicate previews and cached access explanations. Actual
Textual tests traverse event/message/period, inquiry/signals/evidence, retained
service messages, original records, explicit pin replacement and return navigation.
They cover unrelated tab visits, replacement snapshots, compact resize, cancellation
and failures without historical/current-network fallback. No production events or
configuration changes are generated. Existing CPU/wall/RSS/aggregate budgets remain
unchanged; installed Debian/Ubuntu checks exercise Signals reuse and Evidence pinning
with real optional-source absence. Actual new-flow SSH acceptance remains an operator
check, not an inferred result from earlier releases.
