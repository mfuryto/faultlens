# Faultlens 1.2.1 release scope and qualification

The owner authorized official GitHub publication on 2026-11-23. This patch release
ships the corrections merged in PR #78: all four xtables version/save readers keep
their multicall invocation names, valid nftables responses up to 192 KiB are read,
and modal actions are aligned, colored and responsive to narrow SSH terminals.

Port rows assess supported new-flow IP/inet INPUT policy with rule order, defaults,
chain control and source/interface conditions. Allowed, Blocked, conditional and
Unresolved results refer to collected INPUT evidence, not Internet reachability.
Other hooks, NAT/forwarding, unreadable backends and unsupported constructs retain
explicit limits. No external probe, configuration change or dependency change runs.

## Publication gates for 1.2.1

Review the stable-version staging PR, [exact-lock advisory audit](security/dependency-audit-1.2.1.json),
changelog and install instructions. Require source/frontend/resource, native platform,
installed Debian/Ubuntu and CodeQL checks on the PR and exact publication main commit.
The implementation passed 740 tests, 34 performance scenarios and 117 constrained
runs before release preparation; release CI and final assets are checked separately.
An isolated Ubuntu installed-benchmark timeout passed on its single-job rerun after
independent PR and local qualification passed under unchanged budgets.

Build `faultlens_1.2.1_all.deb`, `faultlens-1.2.1-source.tar.gz`, `release.json` and
`SHA256SUMS`. The source archive and reviewed wheels must reproduce the package byte
for byte offline. Qualify the exact final artifact on pinned Debian 12 and Ubuntu
24.04, including installation/upgrade/removal, ten CLI contracts, real installed
TUI/PTY/preferences and the existing installed resource gates. Tag only the verified
main commit; download and compare every draft asset before publication. Preserve
prior releases and only main/staging branches. No APT repository is introduced.

Server feedback on these corrections follows delivery. Synthetic/container checks
are execution receipts, not claims that the reporting server's rules or access are
now verified. See [INPUT scope](architecture/port-accessibility.md) and
[reader corrections](architecture/firewall-fail2ban.md).

# Historical 1.2.0 release scope and qualification

The owner authorized an official GitHub release with a `.deb` on 2026-11-22 to
test SSH statistics, firewall/Fail2ban and port accessibility on the server. All
three steps merged in PRs #74–#76 after their required checks passed. Version
1.2.0 includes these additions and the post-1.1.0 stabilization in PR #73.
The stable version describes this feature set, not a server-health/security verdict.

## Included since 1.1.0

- Paged SSH authentication statistics for boot/hour/day/selected periods, with
  explicit failed/accepted/partial/context counts, reported usernames/peers/time
  buckets, original messages and honest lower bounds or unavailable totals.
- Current firewall rules/defaults/sets and Fail2ban jail status, thresholds/actions,
  reported bans, conditional rule correspondence and bounded unit/file logs.
  Reported action, actual enforcement and the human initiator remain distinct.
- Dual-stack listeners/unconnected UDP bindings, reported owners/current services,
  addresses/routes, conditional policy, DNAT/redirect declarations and compatible
  target-socket references. External verification is separately explained and is
  never performed or inferred from a listener, route or accept rule.
- Accepted native ss padding, independent address/route coverage and retained full
  service-message previews and source navigation in Evidence.

The workspace remains the primary command; CLI commands are documented separately.
No Python dependency change, daemon, automatic recording, privilege grant, external
probe, configuration action, telemetry or cloud integration is introduced. All
accepted administrator evidence remains locally accessible without masking, with
terminal controls escaped and missing/capped sources explained.

## Publication gates for 1.2.0

Review the stable-version staging PR, refreshed [exact-lock advisory audit](security/dependency-audit-1.2.0.json),
changelog and installation instructions. Merge only after source/frontend/resource,
native platform, Debian/Ubuntu installed-package and CodeQL gates pass. Publish the
exact verified main commit after its own checks and CodeQL results are green.

Build `faultlens_1.2.0_all.deb`, `faultlens-1.2.0-source.tar.gz`, `release.json` and
`SHA256SUMS` from that clean committed source and the reviewed wheels. Require the
shipped corresponding source/wheels to reproduce the package byte for byte offline.
Qualify the exact final artifact on pinned Debian 12 and Ubuntu 24.04, including
installation/upgrade/removal, ten native CLI contracts, real installed port-modal
collection, private frontend/PTY/preferences and all 34 benchmark scenarios/39
constrained profiles under unchanged budgets. Preserve GPL/dependency notices.

Tag the verified main commit, upload assets to a draft, download and compare every
asset's bytes/hash and provenance, then publish using the owner's authorization.
Preserve prior tags/assets and only main/staging. No APT repository is created.
Server feedback for these new features follows delivery; container/synthetic passes
do not prove Internet reachability, complete policy, continuous history or detector
accuracy. Source bounds and interpretation remain in the CLI/architecture docs.

# Historical 1.1.0 release scope and qualification

The owner authorized official GitHub publication on 2026-11-22. Version 1.1.0
combines the additive service, process/storage, practical network and coherent
inquiry/evidence work merged after 1.0.1. No 1.0.2 release was published. This is a
local fault-investigation release, not a host-security or detector-accuracy certificate.

## Included since 1.0.1

- General service result/exit/signal explanations, original messages, surrounding
  context and bounded follow-up periods across system services.
- Current process CPU/RSS, reported cgroup service associations and mount-specific
  space/inode review, with inaccessible/partial/read-only sources explicit.
- Three short network intervals, TCP/IPv6 UDP source coverage, numeric local link,
  address/route context, permitted socket owners and explainable review cards.
- Possible scan/authentication/traffic patterns with actual referenced peers/ports,
  alternatives and original records; attack and underlying cause remain unverified.
- History report examples, question/time-based Investigate, Signals derived from the
  same inquiry and fixed Evidence selections across unrelated reads and refreshes.
- Additive inquiry/partition provenance and compatible saved preference keys, with
  collection-purpose and cached-access explanations.

The primary terminal command, explicit CLI/JSON commands and private reviewed
frontend remain available. The runtime/dependency/read-only boundaries documented
below and in [package verification](debian-package.md) still apply. No new Python
runtime dependency, daemon, automatic recording, privilege grant, capture, blocking,
repair, telemetry or cloud service is introduced.

## Publication gates for 1.1.0

The stable version, exact-lock advisory report, changelog and install instructions
are reviewed on staging and merged only after source/platform/resource/CodeQL and
both package CI targets pass. Publication uses that exact verified main commit.

The bundle must contain `faultlens_1.1.0_all.deb`, corresponding committed source
with the reviewed wheels, `release.json` and `SHA256SUMS`. The source bundle must
reproduce the package byte for byte offline. Qualify the final artifact on both
Debian 12 and Ubuntu 24.04, preserving existing install/upgrade/removal, native
CLI/TUI/PTY and resource checks. Verify main checks and CodeQL analysis at the exact
publication commit. Tag only that commit, upload to a draft, download and compare
all asset hashes, then publish under the owner's authorization. Keep only
main/staging branches and preserve prior tags/assets; no APT repository is created.

The [1.1.0 dependency audit](security/dependency-audit-1.1.0.json), dated 2026-11-22,
reports all nine exact requirements without known findings or skipped packages.
It is not proof against unknown vulnerabilities. GitHub CI runs and release.json
identify qualification and exact-source provenance; source/rebuild and target
results are verified during release execution, not assumed from an earlier build.

Earlier owner SSH/server feedback remains valid for its recorded revision. The new
inquiry flow has synthetic frontend and installed package acceptance; live SSH
feedback for that new flow remains operator follow-up. Container tests share a
kernel and do not establish native workload impact or empirical detection rates.
See [acceptance evidence](acceptance/server-qualification.md) and
[the current delivery plan](delivery-plan.md).

# Historical 1.0.1 qualification record

Version 1.0.1 extends the initial local Linux fault-investigation release with
selected-service status, retained unit logs and message explanations. The owner
requested the 1.0.1 Debian release on 2026-11-22. The version number describes
this feature set; it does not certify a server as healthy, secure or attack-free.

## Included

A keyboard-driven terminal workspace (the default command), explicit CLI/JSON paths,
current System/Health/Network views, three problem-centered investigation entries,
reported login sessions, retained journal analysis, original evidence navigation,
existing Atop replay and supported live/archived pstore readers. Collection is local,
bounded, read-only and uses existing access. Preferences are saved per user.
Health service rows open a current-boot unit investigation, retaining all returned
messages and distinguishing supported explanations from unknown messages.

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

The owner is testing the installed package on another server and reported the
AppArmor failure that motivated this service reader. The supplied native output
is not a result of testing the new reader; new-reader feedback remains follow-up. Prior source
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
exact commit as `v1.0.1`. Upload to a draft release, download and verify every asset,
then publish using the owner's explicit authorization. Preserve only main/staging
branches and synchronize staging after the squash merge. No APT repository is created.

The supported fix target is the latest published version; see [SECURITY.md](../SECURITY.md).
Dependency audit results are dated, not a guarantee against unknown vulnerabilities.
Owner account recovery/2FA and broad incident calibration are not independently audited.
