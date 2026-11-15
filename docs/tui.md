# Terminal interface

Run from the trusted checkout, as its owner and normally without root:

```sh
./bin/faultlens tui
```

`./bin/faultlens` also opens the TUI when both input and output are interactive
terminals. With redirected input/output it retains the existing one-shot status
behavior. Explicit CLI commands and `--json` remain independent of the TUI. `health`
is a CLI alias for the existing check observations, including optional `--history`.

Python's optional standard-library curses component and a supported TERM/terminfo
entry are required for the TUI only. An SSH PTY is sufficient; there is no X server,
web interface or local socket server. Missing terminal capabilities produce a short
error and leave the explicit CLI available. No Python package installation is needed.
The UI adapts to small terminals; below 30 columns or 8 rows, resize or quit first.
A sidebar appears from 90 columns/15 rows; narrower screens retain numbered navigation.

## Navigation

| Key | Action |
| --- | --- |
| 1–8, Tab, Shift-Tab | Choose a page; no collection is triggered by navigation |
| r | Replace the current snapshot on a source page |
| Up/Down, j/k | Move through items or scalar lines |
| PageUp/PageDown, Home/End | Page or jump through the current view |
| / | Enter a literal search for the current view; Enter finds, Esc cancels, Ctrl-U clears |
| n, N | Find the next/previous matching row or scalar line, wrapping at either end |
| Enter | Inspect the selected item; open a timeline entry's explained finding; edit/toggle a setting; select a boot for diagnosis |
| e | Inspect original timeline metadata, a boot's metadata without selecting it, or another item |
| Left, Backspace, Esc | Return one level; Esc also cancels a setting edit |
| t | Open the retained main diagnosis timeline |
| ? | Open keyboard, scope and setting help |
| q, Ctrl-D | Quit and restore the terminal |
| Ctrl-C | Interrupt collection/application and restore the terminal |

The global shortcuts apply outside the value editor; Esc cancels that editor first.

Search is case-insensitive and accepts up to 64 printable ASCII characters. It matches
row labels and readable previews, plus full direct scalar values even when their row
preview is shortened. Open an object/list or an original message to search inside it:
unopened evidence trees are not searched recursively. In an open scalar, search uses
the complete lossless JSON-escaped representation; for example, search for `\u001b`
to find an escaped ESC byte. Regular expressions and shell syntax have no special meaning.

A new search starts at the first match. n/N moves between matching rows or scalar
lines, skipping additional matches on the same scalar line. No rows or evidence are
filtered, masked or removed. Search reads only the in-memory view and does not refresh
sources, execute commands or save history. The query lasts only for this session.

There is no automatic polling. On a source page, press r to collect, inspect the
result, and refresh again when wanted. Collection runs synchronously: a busy message
is drawn first, and navigation resumes when the bounded adapters return. Optional
journal/replay queries can take several seconds. Ctrl-C interrupts and exits rather
than pretending a partial operation completed. Existing filesystem reads have no
hard deadline; curses does not add a background worker or daemon to mask this limit.

## Eight pages

1. **System Overview**: existing status observations with their individual states.
2. **System Health**: existing check/dependency observations; optional preservation
   assessment when enabled in Settings. No overall health/security all-clear is inferred.
3. **Network Status**: interface/TCP/UDP sampling and optional local socket evidence.
4. **Security Analysis**: current security counters; after a diagnosis, its historical
   security/SSH/firewall results can be inspected here without another query.
5. **Incident History**: existing bounded multi-boot summaries and the visible boot
   listing. Enter on a boot pins its immutable ID and opens Diagnostics; press r to
   actually collect. Listing a boot is not proof its complete journal is retained.
6. **Diagnostics**: selected-boot findings, retained timeline, reconstruction, original
   journal evidence and explicitly enabled optional source results.
7. **Evidence Explorer**: snapshot collection options and the complete latest report.
   All objects, lists and scalar values can be opened. No fields are privacy-masked.
8. **Settings**: session-only collection options. Nothing is saved to configuration,
   services, recorder policy or disk. Source permissions and existing limits still apply.

Only one report is retained. Collecting another source replaces it, so a page with no
matching report asks for an explicit refresh. Evidence Explorer always refers to the
latest report. A settings-change banner distinguishes old snapshot scope from new
options; existing evidence is never silently relabeled. Refresh drops old browser
references before collection to avoid holding two potentially large reports.

## Collection settings

Use Enter to toggle booleans or edit numeric/date selectors, then Enter to validate.
Esc cancels; Ctrl-U clears the editor. Invalid values leave the prior settings intact.

- `boot_selector`: visible index -128 through 0 or exact 32-character lowercase
  hexadecimal boot ID. History selection pins the ID, avoiding relative-index drift.
- `system_journal`: select accessible system journals; never grants access or elevates.
- `sample_seconds`: 0.05 through 1, default 0.1. Rates still use measured elapsed time.
- `boot_count` / `include_current`: 1–7 previous-boot summaries; current boot opt-in.
- `preservation`: add existing retention/recording checks on System Health refresh.
- `sockets`: opt in to the fixed local ss adapter on Network/Security refresh.
- `search_events`, `search_ssh`, `search_firewall`: existing optional diagnosis queries.
- `atop_date`: empty disables replay; otherwise an existing YYYYMMDD recording.
  `atop_extended` requires a date. No recorder settings are changed or history created.
- `pstore`, `pstore_archive`: opt in to the existing fixed crash-evidence readers.
- `since_us`, `until_us`: optional Unix microsecond receipt bounds through year 9999;
  start must not exceed end. Whole-boot targeted searches retain their documented scope.

All optional source toggles default off. Diagnostics retains ordinary journal originals
for exploration, under the existing 500-record/byte bounds. Atop/pstore originals are
only collected when their source is explicitly enabled. The UI never runs sudo.

## Evidence and safety

A selected finding exposes its complete observation, evidence, source references,
reasoning, thresholds, confidence, limitations and recommendations. Arrays and
objects are browsed by reference rather than serialized into one huge screen buffer.

In an explained finding, open **Referenced source evidence**, then **References**.
Each reference shows its resolution and **Retained source evidence**. Open an entry's
**Original evidence** to inspect the complete retained journal record or Atop sample.
Source locations identify the original list; wrappers hold direct references, not
copies or newly collected data. Current network findings are also available through
**Explained findings** on the Network/Security pages; their counter measurements are
embedded in the finding reference rather than linked to invented raw captures.

Journal links stay inside the finding's source list and require a matching candidate
index plus reference fields, or a unique matching cursor hash and reference fields.
Receipt timestamps alone do not select records. Derived SSH/firewall indicators
follow only their declared source candidate indices and boot ID. Historical Atop
indicators link their observed and baseline sample indices only within the same
captured-output hash; this does not verify recording host/boot identity. Missing or
ambiguous references are reported explicitly without borrowing records from another
query. Unresolved links do not establish that the underlying event did not occur.

Original logs, usernames, IPs, ports, process identities and packet context remain
visible when collected under existing permissions. Binary pstore evidence retains
its existing lossless encoding and hashes.

Scalars are shown as lossless ASCII JSON. Escape characters, bidi controls, Unicode
and newlines appear as explicit escapes rather than executable terminal sequences.
Long values wrap and page without altering the original in-memory value; previews
state when a value is abbreviated and Enter opens the entire value. Use the existing
CLI --json for structured stdout when needed. There is no clipboard integration,
shell escape, pager, automatic export, report file, upload or persistent command history.
The terminal/SSH client itself may retain scrollback; manage that client locally.

The t shortcut navigates only the main retained boot-local timeline. Filtered SSH,
firewall and targeted timelines remain available within their own source objects;
they are not silently merged into a complete or causal chronology. An empty report,
unavailable source, unknown cause or lack of matched indicators never becomes proof
that a host is healthy or secure.

Enter on a timeline entry opens its explained finding, including **Referenced source
evidence**, **Technical details** and the unchanged **Timeline position**. Press Left
to return to the same timeline selection; e opens only the original position metadata.
Inside an SSH/firewall analysis or a broader-search query, open its **timeline** field
for the same navigation within that source. The source list, finding index, rule and
reference must match. Missing, stale or ambiguous links fall back to original metadata
with an explanation; a similarly timed event in another source is never substituted.
Equal timestamps keep their unresolved order and all existing confidence/coverage
limits. Raw timelines reached through Full report/Evidence Explorer remain raw trees.

## Explained readings and findings

Diagnostics' **Recorded resource measurements** entry explains Atop availability,
requested date/window and coverage. Open **Retained samples** for readable interval
CPU and memory snapshots, **Reported coverage** for exact hints, or **Technical details**
for all original data, extended fields and source lines. e opens the original object.
Missing/RESET shares are not presented as zero. A possible gap or overlap does not
establish missing logging, a freeze or attribution to the selected boot.

On Network/Security pages, explicitly requested sockets have a **Socket snapshot**
entry. Open **Socket rows**, then a row, for state/binding explanations and unchanged
**Technical details**. e on a socket snapshot/row opens the original object directly.
No new data is collected by browsing. All numeric endpoints remain visible; local
bindings, socket states and port numbers do not establish external reachability,
application identity or authorization. Empty/unavailable snapshots retain their limits.

Incident History's **Boot summaries** entry opens readable per-boot report counts,
pattern meanings and collection limits. Select **Diagnose this boot** in an explained
summary to pin its immutable ID, then press r on Diagnostics to request fresh evidence
with the current session options. Selection alone does not collect. e opens a summary's
original technical object; **Technical details** remains available inside its explanation.

Source pages now start with Summary and next steps. Enter on a measurement or a
normalized finding explains its meaning, confidence, limits and investigation steps;
Technical details links to the unchanged original object. Guidance entries preview
plain prose, with Enter for complete lists and long values. Settings use readable
labels; their underlying keys, validation and session-only scope are unchanged.
Evidence Explorer and Full report remain raw, complete views. Original message objects
are never promoted to trusted findings merely because they resemble finding JSON.
See [readable results](readable-results.md) for CLI modes and interpretation boundaries.
