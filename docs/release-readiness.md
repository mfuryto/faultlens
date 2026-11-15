# Pre-release readiness and operator acceptance

Faultlens has a bounded CLI/TUI implementation for review. There is no published
application release, chosen project license or claim of production support. This
checklist prepares the initial source-first release; it does not authorize publishing.

The corrected UserDock-style workspace and stabilization scope are reviewed in
[frontend acceptance](architecture/phase-4-acceptance.md) and [product fit](stabilization.md).
Earlier completion statements for the generic curses browser are superseded. Actual
target-host/SSH acceptance remains distinct from synthetic and container verification.

## Run from a trusted source checkout

Use Linux with Python 3.11+. The CLI has no external Python requirement. Install the
optional workspace's wheel-hashed requirements in an isolated environment using the
[TUI guide](tui.md). There are no automatic dependency downloads. Inspect [feature dependencies](dependencies.md)
before adding journalctl/ss/Atop integrations. Missing optional tools affect only their
features. Run Git and tests as the checkout owner, never as root to bypass Git ownership
checks. Diagnostics use current access rights and never elevate themselves.

```sh
python3 --version
./bin/faultlens --help
./bin/faultlens status --json
./bin/faultlens health --json
./bin/faultlens tui
```

In the TUI, status loads initially; Left/Right switches sections, Up/Down selects rows, Enter opens and Esc returns. r refreshes explicitly.
If a source is unavailable, inspect existing permissions and retention locally;
blanket root execution or changing account groups is not an automatic setup step.
No host configuration, recorder or firewall service is installed or enabled.

The combined server test entrypoint is `python3 scripts/server_check.py`; see
[summary states, optional sources and root/native-only scope](server-check.md).

## Deployment acceptance matrix

Before calling a version supported, run and record the following on each selected
Debian/Ubuntu Server release, including at least one actual small one-CPU VPS. Keep
host evidence outside the repository and never upload logs as a default test artifact.

| Scenario | Required observation |
| --- | --- |
| Ordinary user, missing optional tools | Status/check remain useful; unavailable features are explicit; no elevation or install prompt |
| Existing journal access vs denied access | Selected visible/system scope remains accurate; absence/denial never becomes an all-clear |
| SSH terminal, 100x24 and 40x10 | All pages, details, long evidence and help remain navigable; resize and quit restore terminal attributes |
| Ctrl-C during a read-only operation | Application exits cleanly, terminal restores, native child cleanup follows existing runner contracts |
| Current network/socket snapshot | Numeric endpoints stay visible; no remote traffic or external-reachability assertion |
| Historical sources absent or short | No invented baseline, crash identity, attack or root cause |
| Synthetic complete history | Existing automated acceptance matches, with reference-backed Possible indicators |
| Resource-constrained workload | Measure RSS/CPU/wall and whole-machine impact; compare documented targets and record deviations |
| Session settings | Changes affect only later collection; no configuration/report files appear |

Automated process profiles are reproducible with:

```sh
python3 scripts/vps_acceptance.py --iterations 3
```

Those results constrain CPU affinity and virtual address space on the current Linux
host. They do not certify real VM RAM, cgroups, supported distro releases, remote SSH
clients, native journal/Atop disk I/O or detector accuracy. Release acceptance for
actual target machines remains open until results are recorded and reviewed.

## Publication gates

- [ ] Owner explicitly selects/approves a project license; review required notices.
- [ ] Choose release/version/support policy and complete actual target deployment tests.
- [ ] Review all known limitations and false-positive/false-negative behavior; avoid
  presenting heuristic thresholds as calibrated attack probabilities.
- [ ] Required baseline, analysis and CodeQL checks pass for the exact release commit;
  review changes to collectors, terminal safety and source/evidence bounds.
- [ ] Re-run repository/history secret checks and the [publication checklist](security/pre-publication.md).
- [ ] Review the exact source manifest: tracked application, launcher and documentation
  only; exclude local environments, captures, reports, credentials, caches and development output.
- [ ] Owner authorizes the exact release/tag and any distributable artifacts. Do not
  publish a wheel, archive, container, binary or GitHub release merely because main is green.

The optional frontend has a reviewed wheel-hash lock and an isolated CI installation
step. There is no build backend or packaged release. Reproducible distribution
packaging and third-party notices still require review before release automation.

## Updating and rollback

Exit the TUI before updating. Use reviewed main commits from a trusted remote; a clean
checkout and successful tests are required. Preserve any local work separately and
never reset it as part of an update. Do not delete diagnostics or rewrite history.
For rollback, use a separate trusted checkout at the previously reviewed commit and
its documented Python/tool requirements. Faultlens creates no database, daemon,
persistent settings or schema migration requiring rollback. Session settings disappear
on exit; historical evidence remains managed by the existing Linux facilities.
