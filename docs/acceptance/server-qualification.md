# Milestone 3 — operator-server acceptance record

Recorded 2026-11-18. This is the versioned record for real-server evidence under
the [delivery plan](../delivery-plan.md). Automated qualification, owner-reported
execution and explicit operator acceptance are separate evidence categories.

## Owner server A: evidence received

The owner supplied the readable output from
`.venv/bin/python scripts/server_check.py`, invoked as the ordinary checkout owner.
The owner subsequently confirmed that Faultlens is used exclusively over SSH.
The exact execution date, tested commit, OS/Python/tool versions, terminal dimensions
and SSH client were not supplied. The results below describe that reported run;
they are not independently reproduced measurements or an approval of every workflow.

No native logs, identities, endpoints or collected reports are included here. This
record stores acceptance outcomes only; full administrator evidence remains available
locally in the CLI/TUI without masking. Source implementation reference:
[PR 54](https://github.com/mfuryto/faultlens/pull/54). That reference does not establish
which revision the owner tested.

| Check or observation | Received result | What it establishes |
| --- | --- | --- |
| Software/TUI unit suite and repository security checks | Reported pass | The checker reported no failures in these groups; individual test counts were not supplied |
| Performance and constrained resource checks | Reported pass | Synthetic workloads met their checks on this run; real workload impact remains unmeasured |
| Current system measurements | 17 collected | Measurements were available, not a whole-server health verdict |
| Optional tools | 7 detected | Inventory only; individual versions were not supplied |
| Service, logging and recording checks | 15 completed | Checks completed; this does not prove effective defaults or continuous recording |
| Network counters and local socket snapshot | Read successfully | Accessible current-namespace sources, not external reachability or past incident conditions |
| Accessible boot history | Read successfully | Some history was readable; system-wide coverage was not established |
| Optional frontend | Reviewed Textual available | Dependency check passed; actual rendering/navigation requires separate acceptance |
| Reference measurements | 8 agreed within tolerances | Selected readings agreed at check time, not all counters or all times |
| Explicit journald assignments | 6 values not established | Defaults may apply; no configuration change is indicated by this alone |
| System-wide journal | Unavailable in this run | A coverage gap, not evidence that no faults occurred; the summary alone does not determine its cause |
| SSH/firewall real-data detections | No usable messages in the checked accessible logs | Positive detection behavior was not verified against this server's actual incident data |
| Historical Atop replay | Not requested | Historical resource analysis remains unverified in this run |
| Live/archived crash readers | Not requested | Crash evidence remains unverified in this run |
| Server configuration | Checker reported no configuration changes | Reported read-only behavior, not an independent host-change audit |
| SSH usage | Confirmed by owner | Actual remote usage; specific resize, cancellation, navigation and interpretation results were not supplied |

The overall report contained no failed checks and explicitly retained unverified
features. It supports automated server-test execution on one owner server. It does
not complete milestone 3 or establish an error-free, secure or production-supported
server. Earlier journal access troubleshooting is separate from this run; the
current checker result alone must not be relabeled as confirmed permission denial.

## Remaining acceptance gates

| Gate | Current status | Evidence needed to close it |
| --- | --- | --- |
| Exact target identity | Not recorded | Tested commit, OS release, Python and frontend version; no host identity or diagnostic logs required |
| SSH interaction | Usage confirmed; detailed acceptance open | All tabs, quick switching during collection, resize, details, refresh/cancel, normal quit and Ctrl-C work in the actual client |
| Saved preferences | Not confirmed by owner | One valid setting survives restart as the same Unix user; save/load status is understandable |
| Real incident investigation | Not confirmed by owner | Selected boot/time, actual messages, their meaning, source gaps and a sensible next step can be explained through History → Diagnostics → Records |
| Existing administrator access | Not reported for this version | Native-only results with existing authorized access when relevant; no account/group or logging changes required |
| Optional historical/crash evidence | Not requested in received run | Explicit existing recording date/crash readers when applicable; absent evidence remains a gap |
| Workload impact | Not measured | Responsiveness and resource impact observed during normal real workload; synthetic budgets do not substitute for this |
| Materially different second server | No result received | Same workflow and metadata on another target, including source limitations and operator observations |

Unavailable optional evidence does not require installing tools, generating faults,
rebooting or changing server configuration. A workflow may correctly explain why an
incident cannot be reconstructed. Acceptance should assess that explanation as well
as positive findings; missing sources must never become an all-clear.

## One concrete follow-up session

Run as the trusted checkout owner in the actual SSH terminal. These metadata commands
read the checkout/environment only; they do not collect incident evidence:

```sh
cd /home/codex/faultlens
git status --short --branch
git rev-parse HEAD
cat /etc/os-release
.venv/bin/python --version
.venv/bin/python -c 'from importlib.metadata import version; print("Textual", version("textual"))'
stty size
.venv/bin/python bin/faultlens tui
```

Use the same checkout-relative commands if another server uses a different directory.
Do not replace a dirty checkout or add Git ownership exceptions to gather metadata.

1. Confirm System loads automatically. Open every section, switch rapidly while a
   read is running, and stop on one source section. The selected tab must stay
   selected; that source should load when the previous read ends. Failed reads
   remain explicit and can be retried with `r`.
2. Resize to a normal and a compact terminal. Open rows with Enter, original fields
   with `e`, and return with Esc. Distinguish a layout/navigation failure from an
   unavailable source. All retained evidence must remain reachable.
3. In History choose a relevant boot and Investigate this boot. For a known period,
   set start/end with explicit timezone in Settings and reopen Diagnostics. Read
   the answer, actual excerpts and Records. Explain what was reported, what remains
   unknown and the next investigation. Readable zero-match and unavailable-log
   cases must have different explanations. Do not create an incident for this test.
4. Change one harmless collection preference, quit and relaunch as the same user.
   Verify it is retained, then restore its previous value. Preference changes write
   the user's Faultlens settings only, not server configuration.
5. Test `q` and Ctrl-C in separate launches. The shell must return with normal input
   and rendering. Ctrl-C may return exit status 130. If collection ends too quickly
   to cancel, record that case as not exercised rather than passed.
6. Note whether normal server work remains responsive while collecting/refreshing.
   Record the workload and observation, or leave workload impact unmeasured; do
   not infer it from the synthetic benchmark result.

Report results as `passed`, `failed` with the observed symptom, or `not tested` for
each open gate. Do not upload raw host logs or secrets to complete the checklist.
Existing [server-check options](../server-check.md) provide optional native-only,
Atop and pstore checks; rerunning the full software suite is not needed merely to
try another source scope. No release publication is authorized by this record.
