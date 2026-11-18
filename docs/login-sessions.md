# Logged-in users in System

System includes **Logged-in users**, a current native session/accounting snapshot.
Open the row with Enter to see reported username, terminal, login time in UTC and
source address/reported source. Enter on a session explains its state and limitations;
`e` retains the complete original fields. Rows are paged with the ordinary source
controls. No administrator names or addresses are masked.

The same snapshot is included in `faultlens status`: readable output lists retained
rows, `--json` includes `login_sessions`, and `--details` retains technical source
metadata. Login time precision is explicit: logind normally supplies seconds, while
`who` supplies minutes. Unreported name, terminal, time or source remains explicitly
unknown rather than an empty cell, guessed address or invented timestamp.

## Sources and scope

- After a read-only active-state check, prefer the existing local login manager using fixed `loginctl list-sessions` and
  one batched `show-session` query. Capture session identity, reported name/UID,
  terminal, creation timestamp, remote host, state, type and class. No session is
  activated, locked, terminated or signaled; no install/start/control command is issued. If existing logind is not confirmed active, it is not queried.
- If logind is unavailable, unsupported or returns no records, read `who --users`
  without a file argument or `--lookup`. This is the default accounting source,
  not arbitrary files or login history. Fallback evidence and the other source's
  state remain visible; the sources are not merged into potentially duplicate users.
- Commands use the trusted executable catalog, C locale and UTC. There is no remote
  host/machine option, DNS lookup, network probe or automatic privilege elevation.
  `loginctl` and `who` are optional native tools, not new Python dependencies.

The interfaces and field semantics are documented by
[systemd loginctl](https://www.freedesktop.org/software/systemd/man/255/loginctl.html),
[logind session properties](https://www.freedesktop.org/software/systemd/man/255/org.freedesktop.login1.html)
and [GNU who](https://www.gnu.org/software/coreutils/manual/html_node/who-invocation.html).
A logind timestamp describes session creation; a who timestamp describes an accounting
record. Neither independently proves when authentication succeeded or that the user
is still interacting. State/type/class and original fields remain in session details.

## Reading incomplete results

A successful empty result means **No login records reported**, not nobody logged in.
Native accounting may not cover all SSH, graphical, container or application sessions;
entries may be stale or closing. Records are not counted as distinct authenticated
people, authorized activity, attacks or the cause of a server fault.

Unavailable, invalid and over-limit sources never become a successful empty prefix.
If only fallback accounting was usable, System marks the source partial. Missing
source address does not imply a local session. Stored hostnames remain reported
strings and are never resolved to guessed IP addresses; local displays are labeled.
No installation/configuration change follows merely from a missing source.

Each native command retains the existing two-second and 262144-byte bounds. At most
64 session IDs are passed to one validated logind property query; who accepts at most
256 rows. Missing/duplicate properties, changed session identities, unsupported time
formats and unsafe metadata invalidate that source. Bounded completed output that
could not be parsed remains labeled as unparsed source evidence in original fields.
The snapshot is sequential and non-atomic; sessions can change between reads.

This is local administrative context for fault investigation. It does not replace
historical SSH evidence, a complete session inventory or a system-security audit.

Verification: 575 tests passed locally and in the pinned Debian/Python 3.11.18
qualification environment on 2026-11-18. Synthetic positive/missing/empty/invalid
cases cover both sources, fixed read-only commands, UTC isolation, unchanged journal
execution, fallback behavior, native status contracts and actual TUI details/resize.
Native missing-source handling was exercised; actual session usefulness on the
owner's SSH server remains to be checked there.
