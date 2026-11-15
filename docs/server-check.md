# Read-only server test summary

Run the complete set as the non-root checkout owner:

```sh
cd /home/codex/faultlens
python3 scripts/server_check.py
```

The script combines the unit suite (including synthetic PTY/TUI lifecycle tests),
repository policy, ten-iteration CLI/TUI benchmarks, constrained process profiles,
native status/health/preservation, network/socket adapters, visible/system multi-boot
history, selected-boot SSH/firewall diagnosis and free/df reference comparisons.
No Git update, trust exception, dependency installation, service action, account/group
change, sysctl/firewall write or recorder configuration is performed. Synthetic tests
use temporary fixtures and resource limits in their own children; native evidence is
read using the current user's existing permissions. No diagnostic report is saved.

## Reading the result

The default view uses plain-language groups. --details and --json retain the
following technical state codes:

| State | Meaning |
| --- | --- |
| PASS | This check completed or its source responded; not a host-health/security verdict |
| WARN | Host observation, transient comparison mismatch, source partiality or native timeout needs attention |
| MISSING | Tool, source, access, retained history, matching candidates or comparable baseline is unavailable |
| SKIP | Not requested, unsuitable current terminal, manual interaction needed, or repository checks skipped for root/ownership |
| FAIL | Automated check failed, native worker exited unsuccessfully, or its structured response was invalid; investigate the specific check |

A native worker failure is not automatically a confirmed software bug. Missing
history/permissions and empty SSH/firewall evidence do not fail the program tests.
An empty source can verify adapter behavior but cannot exercise positive detections.
Structured results retain advice, totals and an overall PASS/ATTENTION/FAIL state;
--details shows these technical counts alongside the plain-language summary. Exit 0
means no FAIL rows, including ATTENTION; exit 1 means at least one failed check,
2 means invalid arguments/platform, and 130 means interruption. A zero exit code
never asserts a healthy or attack-free server. Review SKIP and MISSING rows as well.

Full repository acceptance needs Git and Python curses. If either is missing, the
affected repository groups are MISSING rather than presented as failed software
tests; unrelated live CLI probes still run. No dependency is installed automatically.

A normal run may take a minute or more. It prints progress to stderr, with the final
summary on stdout. Each repository worker is capped at 120 seconds, each native
worker at 60 seconds, and captured output at 4 MiB. A failed group does not stop the
remaining groups. Native adapters keep their own shorter command/byte limits. Outer
worker interruption allows a short cleanup grace before forced process-group cleanup;
kernel-uninterruptible I/O remains an operating-system limitation.

## Optional historical/crash evidence

Only request an existing recording date; this does not create historical data:

```sh
python3 scripts/server_check.py --atop-date YYYYMMDD --pstore
```

Replace YYYYMMDD with a real local recording date. Extended Atop replay is tested in
both visible and system journal scopes for the selected boot (default 0). Use --boot
-1 for a previous boot. Existing replay-window limits still apply; traffic comparison
requires six comparable contiguous samples. --pstore explicitly tests both fixed
live and archived crash-evidence readers. Neither crash records nor Atop samples are
silently attributed to a selected boot when identity remains unverified.

If the ordinary user lacks system journal/crash access, an administrator can run
only the native checks from an already authorized root terminal:

```sh
python3 scripts/server_check.py --live-only --atop-date YYYYMMDD --pstore
```

The script never elevates itself. Root and non-owner invocations automatically skip
repository/unit/benchmark/profile checks, even without --live-only. Run those as the
checkout owner; no safe.directory exception or ownership change is added. --live-only
can also be used by an ordinary user for a quick native-only check.

## Structured output and failure details

```sh
python3 scripts/server_check.py --json
python3 scripts/server_check.py --details
```

JSON contains summary states/counts/advice, not host logs or diagnostic measurements.
This is a test-summary scope, not privacy masking in Faultlens's administrator views;
original evidence remains available through the regular CLI/TUI. Failed repository
checks can include an explicitly requested final 6000-character excerpt with --details.
Excerpts and all terminal text use reversible JSON escaping for controls/Unicode.
No raw native evidence or captured native traceback is included as a failure excerpt.
Review any output locally before sharing it; no upload or file export is automatic.

The current terminal check verifies curses/terminfo availability without changing
terminal modes or launching the UI. When input/output is redirected, it is SKIP,
not FAIL. The unit suite independently tests a synthetic local PTY. Human navigation,
actual remote SSH behavior and interpretation of original evidence still require:

```sh
./bin/faultlens tui
```

Use r, pages 1–8, Enter, Left, resize, q and Ctrl-C. A synthetic PTY and constrained
process profiles do not replace real small-VPS/distro deployment acceptance.

## Plain-language output

The default view groups related results into **What worked**, **What could not be
tested or verified**, and **What you may need to do**. Failures and observations
requiring review have their own visible section. Individual passing checks and
technical identifiers do not overwhelm the default view.

For example, several missing explicit journald assignments produce one explanation:
defaults may apply, but their effective values were not verified. This is not an
instruction to change journald. An unavailable system journal is explained separately
from an empty accessible SSH/firewall query; a failed listing does not by itself
prove permission denial. Optional historical/crash tests and manual TUI verification
remain visibly untested, rather than being silently treated as passed.

Actions distinguish review of real failures/warnings from optional evidence coverage.
A summary never recommends changing configuration merely to remove a MISSING row.
Skipped repository tests are not described as successful software tests. Missing
requirements remain visible, and genuine warnings/failures are never folded into
harmless default-setting explanations.

`--details` adds every original technical check, its state and advice, exact counts,
limitations and optional bounded repository failure excerpts after the plain summary.
`--json` retains the existing structured schema and classifications. Grouping changes
presentation only: checks, counts, collection, permissions and exit codes are unchanged.
