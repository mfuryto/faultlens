# Faultlens 1.0 release scope and qualification

Version 1.0.0 is the first local Linux fault-investigation release. The owner explicitly
authorized its preparation and publication on 2026-11-19. The version number describes
this feature set; it does not certify a server as healthy, secure or attack-free.

## Included

A keyboard-driven terminal workspace (the default command), explicit CLI/JSON paths,
current System/Health/Network views, three problem-centered investigation entries,
reported login sessions, retained journal analysis, original evidence navigation,
existing Atop replay and supported live/archived pstore readers. Collection is local,
bounded, read-only and uses existing access. Preferences are saved per user.

The `.deb` includes the reviewed Textual closure privately and uses APT for system
Python. No runtime pip, virtual environment, daemon, automatic recording, permission
grant, log-policy change, cloud service or automatic report upload is installed.

## Qualification

| Evidence | Scope |
| --- | --- |
| Owner-server software/resource report and general SSH approval | Ubuntu 26.04/x86_64, Python 3.14.4, Textual 8.2.8; exact source receipt in the acceptance record |
| Source CI/platform qualification | Ubuntu 24.04/Python 3.12 and pinned Debian 12/Python 3.11; full regression and native CLI contracts |
| Package CI | Clean Debian 12 and Ubuntu 24.04; APT dependency resolution, non-root installed CLI/TUI/PTY, native child collection and resource gates |
| Upgrade/removal | RC-to-stable and final-artifact upgrade; user preferences and synthetic evidence survive removal |
| Source/reproducibility | Two builds agree; shipped source plus wheels reproduce the release package offline |
| Security | Source/history secret checks, strict read-only SHA-pinned workflows, CodeQL, and an advisory audit of the exact dependency lock |

The owner plans another Ubuntu-server test after receiving the `.deb`. This is an
ordinary follow-up test, not a functional limitation or release blocker. Prior source
SSH feedback is preserved rather than requested again. Automated containers share a
host kernel and do not establish native workload impact or statistical detection rates.
See [acceptance evidence](acceptance/server-qualification.md).

## Interpretation boundaries

Missing/unreadable logs are unassessed, never an all-clear. A confirmed recorded fault
is not its underlying cause. Journal searches/tails are capped, source receipt time can
differ from event time and clock movement affects chronology. Original references
remain available. Readable zero-match evidence cannot rule out an unrecorded incident.
Atop covers a bounded two-hour window in one existing file; host/boot identity remains
unverified. Pstore fragments are not boot-attributed and missing fragments do not
exclude a crash. Counts are reports, not automatically independent incidents.

Whole-host security/CVE auditing, comprehensive intrusion detection, automatic repair,
remote management, databases and Faultlens daemons are outside version 1.0. Possible
future security/CVE work remains a separate roadmap decision.

## Publication procedure

Merge the reviewed staging PR only after all source/platform/package/security checks
pass. Build from the verified main commit. Qualify the final `.deb` on both targets,
verify the source rebuild and checksums, and wait for main's required checks. Tag that
exact commit as `v1.0.0`. Upload to a draft release, download and verify every asset,
then publish using the owner's explicit authorization. Preserve only main/staging
branches and synchronize staging after the squash merge. No APT repository is created.

The supported fix target is the latest published version; see [SECURITY.md](../SECURITY.md).
Dependency audit results are dated, not a guarantee against unknown vulnerabilities.
Owner account recovery/2FA and broad incident calibration are not independently audited.
