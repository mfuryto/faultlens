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
| Enter | Inspect the selected item; edit/toggle a setting; select a boot for diagnosis |
| e | Inspect a boot's metadata without selecting it, or inspect another item |
| Left, Backspace, Esc | Return one level; Esc also cancels a setting edit |
| t | Open the retained main diagnosis timeline |
| ? | Open keyboard, scope and setting help |
| q, Ctrl-D | Quit and restore the terminal |
| Ctrl-C | Interrupt collection/application and restore the terminal |

The global shortcuts apply outside the value editor; Esc cancels that editor first.
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
