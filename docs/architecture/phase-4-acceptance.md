# Phase 4 implementation and acceptance

Reviewed: 2026-11-15. The keyboard-driven CLI/TUI frontend and refinement baseline
are implemented on staging for review. This is a pre-release engineering acceptance,
not a published release or a claim that every target deployment has been validated.

| Phase 4 priority | Delivered | Acceptance boundary |
| --- | --- | --- |
| Userdock-inspired terminal interface | Eight numbered pages, sidebar on wider terminals, compact SSH layout, keyboard navigation and explicit refresh | Python curses and a usable PTY/terminfo entry are required; no third-party UI dependency |
| Incident/evidence detail | Immutable boot selection, retained timeline navigation, complete object/list/scalar inspection, source originals and confidence/reasoning/threshold views | Existing source limits, permissions and unknown attribution remain visible |
| Navigation/reporting | CLI-independent presentation model, contextual help, health alias, session-only typed collection settings, visible stale-scope banner | One latest snapshot; no persistent preferences, shell escape, export or automatic configuration writes |
| Small-VPS testing | Reproducible one-CPU constrained process profiles with 128/256/512 MiB address-space ceilings, plus real PTY lifecycle tests | These are process constraints on the development host, not booted Debian/Ubuntu VPS images or total VM RAM quotas |
| Resource optimization | Reference-based evidence browser, bounded scalar previews, viewport-only rendering, one report at a time and blocking idle input | Existing native filesystem operations still have no hard deadline; optional synchronous collection can take seconds |
| Initial release preparation | Operator/TUI guide, source-checkout launch instructions, deployment acceptance matrix and release/rollback gates | No license choice, tag, binary package, GitHub release or publication is authorized by this implementation |

## Architecture decision

The specification prefers prompt_toolkit but does not require it. Its upstream
fullscreen model was evaluated against this Linux-only, small-VPS frontend. Python
curses supplies existing terminal setup, key decoding, resize handling, differential
screen updates and restoration with no new pip dependency or installation workflow.
The application owns only a small menu/tree model rather than implementing a
terminal protocol. Future richer widgets can justify revisiting the preferred
library after provenance/license/resource review; no third-party code is vendored.
References: [Python curses](https://docs.python.org/3.11/library/curses.html),
[curses lifecycle](https://docs.python.org/3.11/howto/curses.html),
[prompt_toolkit fullscreen design](https://python-prompt-toolkit.readthedocs.io/en/stable/pages/full_screen_apps.html).

`tui_model` owns typed session settings, source dispatch, a single report and browser
references. It imports no curses and writes nothing. The existing collector/rule
modules remain the data source. `tui` owns screen layout, key dispatch and a bounded
ASCII option editor; it never interprets evidence as terminal markup. `curses.wrapper`
restores the terminal on normal completion or exceptions. Ctrl-C exits with 130;
capability/runtime failures return 1 without printing source exception contents.
Redirected TUI invocation fails before collection; explicit CLI JSON remains usable.

No background thread, process, daemon, database, telemetry, polling loop or new
external service is introduced. Collection remains synchronous and on demand.
Dropping the old report and navigation references before refresh avoids duplicating
large evidence trees. Rendering slices only visible rows or scalar lines; it never
serializes an entire nested report just to display the first page. The original
report remains available for inspection without privacy-based suppression.

## Automated acceptance

Run without root as the source-checkout owner:

```sh
python3 -m unittest discover -s tests -q
python3 scripts/security_check.py
python3 scripts/benchmark.py --iterations 10
python3 scripts/vps_acceptance.py --iterations 3
```

Tests cover all eight pages, source dispatch, optional-source consent through settings,
atomic validation, history-to-immutable-ID selection, source scope, reference-preserving
navigation, reset/replacement of reports, stale-setting provenance, terminal-control
escaping, long originals, help/depth limits, compact/resized screens and no idle polling.
The real PTY test supplies invented collectors, drives keys, changes dimensions and
compares terminal attributes before/after normal quit and SIGINT. No diagnostic
collection from the CI host, failed login, attack traffic or firewall write is needed.

Current-view literal search adds /, n and N without filtering evidence or collecting
new data. Coverage includes row wraparound, readable units, complete escaped scalars,
line navigation after resize, cancel/clear, input bounds and unchanged source references.
The real PTY navigation also enters a search before terminal restoration checks.

Explained findings expose reference resolution against their own retained source
records. Tests reject cross-query substitution, timestamp-only selection, stale/copied
finding objects, invalid candidate indices, ambiguous records and mismatched recording
hashes. Derived log indicators and historical Atop baselines keep original evidence by
reference, with explicit missing-link counts and unchanged confidence. The integrated
TUI benchmark includes opening a derived finding's linked evidence.

The benchmark adds initial TUI status and an integrated TUI diagnosis with 500 ordinary
journal records, both bounded log sources, six extended Atop samples, 32 interfaces
and both pstore readers. It measures complete source models and actual renderer
calls with a synthetic screen, not a screenshot of live evidence. Existing CLI modes
continue independently. The constrained harness binds each fresh child to one allowed
CPU, enforces RLIMIT_AS and RLIMIT_CPU, and checks the same RSS/CPU/wall budgets.

## Release and deployment boundaries

See [the TUI guide](../tui.md), [resource measurements](../benchmarks.md), and
[release readiness](../release-readiness.md). A real supported Debian/Ubuntu small
VPS still needs the documented operator smoke/SSH tests, and detection thresholds
still need labeled-data calibration before production claims. A constrained process
is not a substitute for kernel, distro, terminal, permission, disk-latency and workload
variation. These open acceptance items are explicit, not marked as completed.

The repository remains pre-release. The project owner must approve a project license
before any licensed distribution. No license is selected and no release is published.
The existing required security checks and solo-maintainer merge policy remain in
force; no new manual GitHub setting is required by this frontend.
