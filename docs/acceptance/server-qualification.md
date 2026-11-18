# Milestone 3 — operator-server acceptance record

Recorded 2026-11-18. This is the versioned record for real-server evidence under
the [delivery plan](../delivery-plan.md). Automated qualification, owner-reported
execution and explicit operator acceptance are separate evidence categories.

## Owner server A: latest evidence and SSH feedback

The owner supplied a new combined server-check result after updating staging and
then reported that everything appeared to work over SSH following the concrete
interaction checklist. This is a general owner-reported SSH smoke-test pass; no
failures were reported. Individual checklist outcomes, the SSH client and measured
workload impact were not supplied. Do not require the owner to repeat the same broad
smoke test merely because its outcomes were not itemized.

| Context or check | Latest owner-reported result | Scope |
| --- | --- | --- |
| OS / architecture | Ubuntu 26.04 / x86_64 | Observed target; not an automatic extension of production-support claims |
| Python / Textual | 3.14.4 / 8.2.8 | Runtime versions recorded by the checker |
| Checkout HEAD at start | `a6d667107cf32b518764f6c490521d92f33340a0` | Revision observation only; local edits and changes during execution were not verified |
| Terminal | 158 columns × 39 rows; interactive input/output | Recorded size; actual SSH use and general interaction confirmed separately by owner |
| Software/security/performance/constrained tests | All groups reported pass | No test failures; the pasted summary did not include individual test counts |
| Current measurements / reference comparisons | 17 measurements; 8 comparisons agreed | Source availability and selected comparison tolerances, not host-health certification |
| Optional tools / readiness checks | 9 detected; 15 checks completed | Tool versions and effective logging defaults are not established by counts |
| Network / socket / session sources | Readable | No completeness, user-activity or external-reachability claim |
| Visible journal investigations | Problems now, automatic recent period and Before restart queries readable | Some sources or usable incident records missing; positive detection not verified |
| System journal investigations | Unavailable in all three modes | No absence of faults established; the result does not determine the access/availability cause |
| Journal settings | 6 explicit assignments not established | Defaults may apply; no configuration change indicated by that fact alone |
| SSH / firewall positive detections | No usable messages in the checked accessible logs | No conclusion about absent events |
| Atop replay / crash readers | Not requested | Optional historical evidence remains unverified |
| Manual SSH smoke test | General pass reported after the checklist | Navigation/use feedback accepted at this scope; specific cancellation, preference and incident outcomes were not itemized |

The exact execution date was not supplied. This receipt supersedes the older run
for recorded target context and current source-coverage outcomes, not for unrelated
claims about source authenticity, fault absence or complete server acceptance.
The owner-server observation is Ubuntu 26.04/Python 3.14.4, distinct from the
Debian 12/Python 3.11 and Ubuntu 24.04/Python 3.12 automated qualification candidates.
No native messages, user identities or endpoints are copied into this record.

## Owner server A: earlier evidence (retained history)

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

## Acceptance gates and outcomes

| Gate | Current status | Evidence needed to close it |
| --- | --- | --- |
| Exact target context | Recorded for latest run | Source cleanliness and execution date remain unverified; no repeat metadata request needed for this run |
| SSH interaction | General owner-reported smoke-test pass | Preserve the general approval; ask for specific outcomes only if needed to investigate a defect or qualify an unexercised case |
| Saved preferences | Included in requested smoke-test checklist; no separate result supplied | General SSH approval is recorded; persistence is not independently attested as a separate result |
| Real incident investigation | Not confirmed by owner | A problem now, chosen period across restarts or pre-restart inquiry shows actual messages, source gaps and a sensible next step through Investigate → Records |
| Existing administrator access | Not reported for this version | Native-only results with existing authorized access when relevant; no account/group or logging changes required |
| Optional historical/crash evidence | Not requested in received run | Explicit existing recording date/crash readers when applicable; absent evidence remains a gap |
| Workload impact | Not measured | Responsiveness and resource impact observed during normal real workload; synthetic budgets do not substitute for this |
| Materially different second server | Unavailable: owner has only this server; known limitation | Retain the gap; owner explicitly authorized package engineering to proceed without a second field target |

Unavailable optional evidence does not require installing tools, generating faults,
rebooting or changing server configuration. A workflow may correctly explain why an
incident cannot be reconstructed. Acceptance should assess that explanation as well
as positive findings; missing sources must never become an all-clear.

## Recording context with the server checker

New server-check runs include a local context receipt in both readable and JSON output:
OS ID/release, Python, architecture, frontend version, checkout HEAD observed at the
start and actual terminal dimensions when available. Run the checker directly in the
SSH terminal to record its interactive dimensions; piping or redirecting it correctly
leaves output-terminal dimensions unavailable. No hostname, username, remote URL,
SSH peer, raw environment or diagnostic evidence is included in the receipt. It is
printed only; no upload or new report file is created.

The revision is an observation, not proof of the source tested: local edits and changes
during execution are not verified. Continue to report checkout status separately.
Root/non-owner runs skip Git revision collection without changing Git trust or ownership.
Unavailable metadata does not fail software checks or establish unsupported software.
An interactive terminal is not proof of SSH use, correct rendering or useful findings;
operator acceptance remains explicitly unrecorded. Record actual outcomes in the table
above only after feedback. Older results are not retroactively attributed to a revision.

## One concrete follow-up session

Run as the trusted checkout owner in the actual SSH terminal. The checker prints the context receipt
and runs bounded live checks with existing access. Its output contains summaries,
not original incident evidence:

```sh
cd /home/codex/faultlens
git status --short --branch
.venv/bin/python scripts/server_check.py --live-only
.venv/bin/python bin/faultlens
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
3. Open Investigate and choose Problems now, A selected period, or Before restart.
   For a known period, enter both boundaries with explicit timezone; boot is optional. Read
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
If a usable real incident is unavailable, use the separately labeled
[synthetic investigation walkthrough](investigation-walkthrough.md) to review the
positive OOM case and the unmatched/unavailable distinction. Record that feedback as
synthetic only; the real-incident and native-source gates remain open.
Existing [server-check options](../server-check.md) provide optional native-only,
Atop and pstore checks; rerunning the full software suite is not needed merely to
try another source scope. No release publication is authorized by this record.

The earlier report predates the problem-centered workflow correction; the latest
report and general SSH feedback above concern the corrected entry points. The
synthetic walkthrough remains explicitly synthetic. Real incident reconstruction,
measured workload impact and materially different second-server acceptance remain
open; general owner-server SSH approval does not close these separate gates.

## Owner decision: package engineering proceeds

The owner confirmed that no other real server is available and explicitly authorized
starting the `.deb` package with required dependencies. Second-server SSH acceptance
is therefore an unavailable field-qualification limitation, not a request to provision
a server or a blocker for package work. Isolated Debian/Ubuntu installation/process
tests do not close it. The existing source-checkout SSH approval remains accepted;
the next owner test should exercise the installed package once available. Real
incident/workload evidence remains limited. This decision does not publish a release
or extend production-support claims.
