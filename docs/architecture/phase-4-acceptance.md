# Corrected UserDock-style frontend acceptance

Reviewed: 2026-11-15. Earlier phase-completion claims for the generic curses/browser
frontend did not establish parity with the requested UserDock workspace. This review
supersedes that claim and defines acceptance of the corrected implementation.

## Reference and implementation

The locally available UserDock reference uses Textual App, Header, status Static,
TabbedContent/TabPane, row-cursor DataTables, modal screens and Footer. Its Left/Right
bindings select the main sections; Up/Down selects records and dialogs expose actions.
Faultlens now implements that structure with eight domain sections. It does not copy
UserDock's account-changing operations or require administrator privileges to launch.

| Requirement | Corrected implementation | Acceptance |
| --- | --- | --- |
| UserDock navigation | Horizontal tabs, arrow-key section/row navigation, modal details and settings, fixed status/footer | Pilot drives actual key events, focus and wrapping rather than testing an independent model only |
| Domain workspace | Measurement/status, network, finding/source, boot and evidence tables | Primary UI is domain records; complete raw trees are secondary evidence views |
| Detailed evidence | Finding references, source batches, timelines, original logs, Atop samples and crash fragments | References remain source-scoped; unknown attribution/confidence and raw values remain intact |
| Responsive reads | Fixed-argument CLI child, bounded output and deadline, graceful interrupt before force, no concurrent reads | Synthetic subprocess and UI cancellation tests; no shell, elevation or writes |
| SSH layout | Adaptive columns, dialog input focus, resize, normal/interrupt restoration | 100x30, 80x24, 40x10 and real PTY checks |
| Dependency strategy | Optional Textual 8.2.8 and complete wheel-hash closure | Exact versions, wheel-only CI install, lock mutation tests and advisory review; CLI has no external Python requirement |
| Resources | Paged source rendering and bounded latest-source caches | CLI <50 MiB, Textual <80 MiB regression bounds; one-CPU/address-space profiles remain process tests |

## Model, privileges and terminal safety

`workspace` maps retained reports to domain tables. `textual_app` supplies widgets,
focus, dialogs and cache provenance. `ui_collection` invokes fixed CLI arguments in
an isolated child using the current interpreter, controlled environment, no stdin or
shell and bounded stdout/stderr. Esc cancels and q/Ctrl-C clean up collection before
terminal exit. Read-only coverage uses administrator defaults; system-only journal scope and dated
Atop replay stay explicit. Startup loads status and opening another source tab
loads it automatically. Revisits reuse snapshots; changed options load on re-entry.
Reads stay serialized and cancelled/failed attempts do not create retry loops.
Native filesystem calls retain the documented kernel-uninterruptible-I/O limitation.

One latest snapshot per source section is retained. A section is dropped before its
replacement; Evidence shares source references while current Security remains separate
from cached historical diagnoses. Times, report
commands and changed-option notices remain visible. No permanent diagnostic cache or background
polling is introduced. Validated per-user TUI preferences are saved separately, never
source evidence; see [preference storage](../tui.md#saving-preferences).

Rich Text cells contain literal escaped source values. Framework developer logging,
remote devtools and alternate-driver environment hooks are disabled. Exception locals
are never rendered by the frontend. No clipboard action, automatic report, decoding
to files, upload, account operation or host configuration writer is added.

## Verification

Install the optional frontend in an isolated environment, then run:

```sh
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-tui.txt
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/python scripts/security_check.py
.venv/bin/python scripts/benchmark.py --iterations 10
.venv/bin/python scripts/vps_acceptance.py --iterations 3
.venv/bin/python scripts/server_check.py --live-only
```

The real frontend is exercised by Textual Pilot and a PTY. Tests include modal
keyboard routing, compact layout, source pagination, selection, settings rejection,
original records, Rich/terminal escaping, bounded output, cancellation/reaping and
fatal-error confidentiality. Benchmarks render the actual frontend with synthetic
bounded evidence; the removed curses renderer is not used as an acceptance proxy.

Final local verification passed 465 tests on Python 3.14.4 and Python 3.11.
The latter suite ran in an offline container with read-only sources, no network,
capabilities dropped and a 512 MiB memory ceiling. All 26 benchmark modes and 45
constrained process profiles passed. A dated advisory scan of the nine pinned
frontend dependencies reported no known vulnerabilities; this does not cover unknown
flaws or constitute a security guarantee.

The default system-Python CLI is also checked independently of the optional packages.
Compatibility/container and advisory evidence is recorded with the final PR; it does
not substitute for actual server, terminal-client or production incident acceptance.
See [stabilization and product fit](../stabilization.md) for exact remaining gaps.

## Deployment and release gates

Actual selected Debian/Ubuntu hosts, SSH clients and at least one small VPS still
need operator acceptance. Labeled incident calibration, stronger boot/recording
identity and complete shutdown verification remain separate product gaps. The owner
has since approved GPL-3.0-or-later; see [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
A supported release policy and exact release publication still require owner decisions.
No application release is published. Existing main/staging protection and required
security checks remain in force; the reviewed CI policy now allows only the exact
hash-checked optional frontend installation step.

## Security coverage stabilization

Security no longer relies on finding rows alone. A zero-match live sample retains
coverage, counter availability, socket state and an Unknown attack assessment. A
separate navigation row opens existing selected-boot SSH/firewall diagnostics without
changing source settings. Loading/cancel/failure rows, original evidence and empty
source-view explanations are tested through the actual UI, including 40x10 layout
and immediate navigation after the first status result.

The synthetic acceptance matrix includes stable counters, positive supported growth,
partial/unavailable counters, unrequested/unavailable/empty/listening sockets, preserved
originals and historical/current scope separation. It is behavioral validation, not
real-incident detector calibration or a security guarantee.
