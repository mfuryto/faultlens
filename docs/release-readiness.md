# Pre-release readiness and operator acceptance

Faultlens has a bounded CLI/TUI implementation for review. There is no published
application release, chosen project license or claim of production support. This
checklist prepares the initial source-first release; it does not authorize publishing.

## Run from a trusted source checkout

Use Linux with Python 3.11+; the TUI also needs Python curses and a supported terminal.
There are no pip requirements or automatic dependency downloads. Do not install
prompt_toolkit just to use this frontend. Inspect [feature dependencies](dependencies.md)
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

In the TUI, press r for the initial snapshot, 1–8/Tab to navigate and ? for help.
If a source is unavailable, inspect existing permissions and retention locally;
blanket root execution or changing account groups is not an automatic setup step.
No host configuration, recorder or firewall service is installed or enabled.

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

No new build backend, runtime package lock or dependency-installing workflow is needed
for this source-first preview. Reproducible distribution packaging and third-party
notice review are required before adding packaged dependencies or release automation.

## Updating and rollback

Exit the TUI before updating. Use reviewed main commits from a trusted remote; a clean
checkout and successful tests are required. Preserve any local work separately and
never reset it as part of an update. Do not delete diagnostics or rewrite history.
For rollback, use a separate trusted checkout at the previously reviewed commit and
its documented Python/tool requirements. Faultlens creates no database, daemon,
persistent settings or schema migration requiring rollback. Session settings disappear
on exit; historical evidence remains managed by the existing Linux facilities.
