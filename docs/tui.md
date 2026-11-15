# UserDock-style terminal workspace

Faultlens uses the same interaction structure as the locally reviewed UserDock
reference: Textual Header, status line, horizontal TabbedContent, row-cursor
DataTables, modal screens and Footer. The old curses renderer is removed. The
primary workspace is domain tables, not a JSON/object menu. CLI collectors and
structured output remain independent of Textual.

## Install and launch

Use a trusted checkout as its owner:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-tui.txt
.venv/bin/python bin/faultlens tui
```

After activating `.venv`, `./bin/faultlens` also opens the workspace when attached
to an interactive terminal. Explicit CLI commands work with system Python without
these optional packages. No dependency downloads or installation occur at launch.
The reviewed Textual version and complete pure-Python wheel closure are pinned in
requirements-tui.txt; do not mix UserDock's environment with this project's.

Faultlens does not need root to launch. Source access depends on existing account
permissions. No elevation, account/group changes or host configuration writes occur.

## Navigation

| Key | Action |
| --- | --- |
| Left / Right | Previous / next main section, wrapping at either end |
| Up / Down, PageUp / PageDown, Home / End | Move through table rows |
| Enter | Open the selected record, finding, source or setting |
| Esc | Close the current dialog; at the workspace, cancel active collection |
| e | Open unchanged original evidence for the selected row/source |
| s | Explain the current snapshot or source coverage |
| r | Explicitly collect the current source section |
| /, n, N | Literal table search; next / previous match without filtering rows |
| Ctrl-Left / Ctrl-Right | Previous / next batch in a source-record dialog |
| q | Quit; in the raw evidence browser, close that browser |
| Ctrl-C | Cancel collection and quit with 130, restoring the terminal |
| ? | Keyboard, collection and confidence help |

Within an input dialog, arrow keys edit the input instead of switching sections.
Enter applies validated session options; Esc cancels. Boolean collection options
toggle through their table row. Changes affect later collection only.

System status loads on startup. Each source section loads when first opened,
then reuses its snapshot on later visits. Changed collection options are applied
when the source section is reopened; r always requests a fresh read. Evidence and
Settings do not collect. Only one read runs at once; switching during a read loads
the currently selected source section after it finishes, without querying intermediate
tabs. Failed or cancelled reads do not retry in a loop; r retries. Read-only coverage defaults on; the scope exceptions below remain explicit. Collection runs in a bounded,
cancellable child process so tabs and cancellation remain responsive. A cancelled
refresh retains no replacement report. Native readers retain their own access and
resource constraints; kernel-uninterruptible I/O remains an operating-system limit.

## Sections and evidence

| Section | Main table / action |
| --- | --- |
| System | Current measurements, values and source states; Enter explains each reading |
| Health | Tool/service/recording readiness observations; missing data is not host failure |
| Network | Interface rates and protocol counters; explicitly requested sockets open a separate endpoint table |
| Security | Current network indicators, source coverage and sockets, including zero-match states; a separate link opens selected-boot SSH/firewall history |
| History | Visible boots, examined/unexamined status, report counts and retained-record counts; Select boot pins its ID and opens Diagnostics, which loads the selected boot |
| Diagnostics | Grouped reports and separate journal/security/recording/crash sources; open groups to inspect individual reports |
| Evidence | Explicit access to complete original report/source trees |
| Settings | Typed per-user preferences, saved on valid changes; no server configuration editor |

Repeated reports are grouped in the overview rather than called separate incidents.
Source dialogs render at most 64 rows per batch, show the retained total and retain
all records; Next/Previous or Ctrl-Right/Left reach the other batches. Pagination is
a rendering bound, not source truncation or redaction. Details explain observation,
meaning, confidence and next steps. Original and Records open retained evidence.
Raw trees are secondary inspection tools, never the main navigation model.

The workspace retains at most one bounded snapshot per six source sections. Replacing
a section drops its prior report first; Evidence shares source references. Security
uses its own current report and never falls back to a cached diagnosis. Timestamps, actual report command and changed-option
notices distinguish stale or differently scoped results. No diagnostic snapshots or evidence are persisted.

## Safety and acceptance

Source strings are literal Rich Text with reversible ASCII/JSON escaping, never
markup, links, shell syntax or terminal sequences. Names, IPs, ports, original logs,
process identities and crash content are retained without privacy masking. Base64
represents original bytes; browsing does not decode them to files. Textual developer
endpoints, alternate drivers and log destinations are disabled. Fatal UI errors do
not render source exception text or locals.

Tests drive the real Textual app through Pilot, plus a real PTY for normal quit,
Ctrl-C and terminal restoration. Layout/navigation are checked at 100x30, 80x24 and
40x10, including resize and input focus. Synthetic screenshot previews contain no
host evidence. Actual server/SSH-client acceptance remains necessary; see
[server checks](server-check.md), [stabilization and product fit](stabilization.md)
and [frontend acceptance](architecture/phase-4-acceptance.md).

## Synthetic interface previews

These captures render the actual frontend using invented test data, never host logs.

![System workspace with domain columns](previews/workspace-system.svg)

![Finding meaning and follow-up dialog](previews/workspace-dialog.svg)

Timeline details also retain a separate original position (`p` / Position), so the
finding and its timeline reference can both be inspected without guessing identity.

## Defaults and lifetime

Saved preferences are loaded at launch. Without a valid saved file, Faultlens
uses the administrator defaults: current boot in the overview, recording/retention
checks, socket endpoints, broader kernel/service searches, SSH/firewall searches, and
live/archived crash-evidence reads are On. These read existing accessible sources;
they do not enable logging, configure recorders, grant access or create reports.
Missing sources remain unavailable evidence, never a reason to install or elevate.

"Use accessible system journals" remains Off: this selects system-only scope rather
than enabling journal collection. Accessible journal evidence is already read; forcing
system-only scope can hide usable personal records when system access is unavailable.
Enable it when system-only evidence is intended and existing access permits it.

Atop date remains unset, and extended replay stays Off until an existing date is
selected. No recording/boot association is guessed. Date boundaries remain unset
unless the operator wants to narrow the journal search. These choices preserve source
scope; they are not disabled general monitoring.

## Saving preferences

The normal TUI entrypoint loads `${XDG_CONFIG_HOME}/faultlens/settings.json`, or
`~/.config/faultlens/settings.json` when XDG_CONFIG_HOME is unset, empty or relative.
Valid edits and boot selection save immediately. There is no need to quit normally
to save; invalid edits leave the previous file intact. Merely launching the TUI does
not create a file. CLI observations and server configuration are unchanged.

Only the fixed collection settings are stored: booleans, sample duration, overview
count, selected boot, Atop date and optional journal boundaries. No reports, snapshots,
search text, paths to arbitrary evidence, logs or credentials are saved. Boot IDs,
dates and boundaries retain their literal selection across restarts; clear or change
them when investigating another period. Relative boot indices remain relative.

Each Unix account has its own preferences. Root does not load another user's file.
Configuration directories/files must belong to the current effective user, with no
shared writes to the base directory and private app-directory/file permissions.
New app directories use 0700 and files 0600. Symlink components, non-regular files,
hardlinks, wrong owners, unsafe permissions, unknown schema/fields, invalid types or
ranges and files above 8 KiB are rejected. All fields validate before any are used.
Writes use a private temporary file, flush/fsync and atomic replacement; existing
unsafe files are never chmodded or followed.

Settings shows the path and load/save status. If a file is invalid, defaults are used
with a notice. If saving fails, the current session remains usable and explicitly
reports that persistence was not confirmed. Concurrent instances use the last
successful save. To reset defaults, remove the preference file while Faultlens is
closed. No preference migration or diagnostic export is performed.

A supplied initial TUI sample duration seeds first-launch defaults; a saved preference
takes precedence. Use Settings to update that duration for later launches.

## Security coverage and empty results

Security checks a short current-network-namespace counter sample and requested local
sockets. With no matched indicators, it still shows readable counter coverage, socket
source state and the Unknown attack assessment. Available/partial/unavailable describes
source collection, not a safe/compromised verdict. Original readings remain accessible.

The SSH and firewall history row opens Diagnostics using the existing selected boot,
journal scope and search toggles. The row shows whether each search is On/Off. It does
not change preferences, query another boot or reuse historical findings as live network
observations. Disabled searches and missing journal access remain separate limitations.

Loading, cancellation and unsuccessful collection have their own visible rows even
when no snapshot exists. Esc cancels; r retries after cancellation/failure. Collection
starts after the first screen layout so immediate navigation is not reset by tab setup.
Empty source tables describe this view only: unclassified original records may still
exist; s explains source coverage and e opens originals.

![Security workspace without warnings, using invented data](previews/workspace-security.svg)
