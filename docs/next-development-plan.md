# Approved next development sequence

Approved 2026-11-22: SSH statistics, firewall/Fail2ban, then port accessibility.
The four-step 1.1.0 delivery is complete; post-release stabilization merged in
PR #73. The [delivery plan](delivery-plan.md) remains the execution record.
Finish and verify one coherent step before starting another. SSH statistics merged
in PR #74 and firewall/Fail2ban in PR #75. Port accessibility merged in PR #76. All three approved steps are delivered.
The owner subsequently authorized an official 1.2.0 release for server testing;
see [release scope and gates](release-readiness.md).

| Order | Work | Administrator outcome | Acceptance |
| --- | --- | --- | --- |
| 1 | SSH authentication statistics | See when, how often and which reported usernames/peers appear in authentication reports since boot, during the last hour/day or a chosen period | Paged bounded collection beyond the old 500-row tail; explicit failed/accepted/partial/context counts; per-user, peer and time summaries; original records; honest lower bounds and unavailable totals |
| 2 | Firewall policy and Fail2ban attribution | Understand what is blocked, why and which component reports initiating it | Inspect active native rules/policies/sets, supported counters and retained logs; distinguish a Fail2ban-reported ban from matching active enforcement; state unknown administrator identity where audit evidence is absent |
| 3 | Port accessibility | Understand a listener's binding, reported service, local filtering and forwarding/container path | Separate local listening, policy-based assessment and actual external test evidence; IPv4/IPv6 and source restrictions stay explicit; no automatic external scan |

## Step 1: delivered in PR #74

See [SSH design and bounds](architecture/ssh-statistics.md). Network opens the
explicit SSH history reader. CLI uses `faultlens ssh`, existing journal scope,
optional immutable boot ID and timezone-qualified period boundaries. Count explicit
authentication reports rather than adding invalid-user/PAM context to failures.
An accepted method is not a confirmed complete or authorized session. Retain original
usernames, peers and messages without privacy masking, with terminal controls escaped.
No persistent counters, recording policy, daemon, database or extra dependency.

## Step 2: delivered in PR #75

See [firewall/Fail2ban design and bounds](architecture/firewall-fail2ban.md). Network
and `faultlens firewall` expose current rules/defaults, sets, jail status/settings,
qualified same-address correspondence and retained unit/file log context. Human
initiator and final enforcement remain unverified when evidence cannot establish them.

### Interpretation boundary

Read real nftables/iptables state, recognizing compatibility/frontends such as UFW;
do not treat multiple views of the same backend as independent corroboration.
Interpret supported chain/hook priority, defaults, sets, direction and relevant
forwarding. Unsupported paths remain unresolved rather than guessing a verdict.
Read-only Fail2ban state/logs may explain jail, reported threshold, timing and action;
current settings are not proof of the settings at an older ban. A chain name alone
is not verified rule ownership. A ban through Fail2ban need not identify the human
who requested it. Existing audit evidence is needed for human attribution.
No ban/unban, rule changes, rule tracing that changes state or production attack tests.

## Step 3: delivered in PR #76

See [port evidence, source bounds and acceptance](architecture/port-accessibility.md).
Network and `faultlens ports` connect dual-stack bindings, reported owners/services,
addresses/routes, conditional rules/defaults and translation declarations. Open a
port or translation for actual evidence and a separate external-verification guide.
The tool performs no remote probe and does not import unverifiable test assertions.

### Interpretation boundary

Join actual TCP listeners/UDP bindings with addresses, reported service and supported
filter/NAT/container-publishing paths. A listening socket or local accept rule alone
cannot establish Internet accessibility. Router/provider policy, NAT and source
restrictions can remain outside local visibility. An optional separately performed
external test must identify source, protocol and time, and only establishes that
observed path. TCP and UDP have different validation requirements. No automatic
remote probe, cloud integration or false global reachable/closed verdict.

## Shared completion criteria

- Useful explanation, actual evidence, scope/time, coverage and next investigation.
- Read-only existing access, bounded/cancellable commands and no automatic exports.
- Synthetic positive, ordinary, ambiguous, missing, capped and malformed cases;
  actual frontend original-record navigation and source-failure distinctions.
- Unchanged dependency locks and CPU/wall/RSS budgets; required source/security,
  Ubuntu/Debian platform, installed-package and CodeQL gates before merge.
- Only staging/main, no force push/deletion. A new ordinary GitHub release requires
  the owner's release instruction; published tags/assets remain immutable.

## Deferred work

The earlier proposed service-history periods, incident-aligned Atop recordings and
storage-fault follow-up remain candidate work after this approved network sequence.
No implementation or new collection bounds for those proposals are implied here.
Hardware tools/active tests and additional privileges are separate scope decisions.
Broader security/package-CVE assessment remains possible future roadmap scope,
not part of this delivery. Automatic repair, blocking and packet capture are excluded.

## Post-1.2.0 owner feedback

The owner requested clearer aligned modal buttons, correction of the nftables
reader-size failure and all four xtables sources, and actual per-port firewall
assessment rather than repeating external reachability uncertainty. Work on staging
keeps the new-flow INPUT interpretation explicitly separate from Internet testing,
with source restrictions/unsupported paths visible. These changes merged in PR #78
after source, UI, resource, installed Debian/Ubuntu and CodeQL checks passed. The
owner authorized official 1.2.1 publication on 2026-11-23 with the qualified `.deb`,
corresponding source and checksums. No prior release/tag/asset is changed.
