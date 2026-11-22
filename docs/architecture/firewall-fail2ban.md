# Firewall and Fail2ban evidence

Approved network step 2 adds an explicit Network action and `faultlens firewall`.
It collects current policy and jail state alongside bounded retained logs, explaining
conditional blocking expressions and reported bans. It does not change policy,
evaluate every packet path or certify external port accessibility (step 3).

## Independent sources and normalization

Read fixed numeric nftables JSON (`nft -j -n -a list ruleset`), IPv4/IPv6
`iptables-save -c`, backend version strings, `ufw status verbose` and existing
`fail2ban-client status`. Trusted absolute paths, fixed argv, no shell, controlled
environment, two-second/256-KiB subprocess capture and existing access apply.
Missing, unsuccessful, unsupported and empty readable sources remain distinct.
No dependency is installed, daemon started or privilege granted. These optional
tools use their upstream installed licenses; none is bundled or imported.

Normalize nft tables/chains/rules/sets/elements and iptables-save tables, policies,
options, targets, chain links and counters. Preserve originals and unknown objects,
expressions, comments and expiry/timeout metadata. Decode simple source-address/set
and port/protocol predicates for explanations; complex maps, concatenations, ipsets,
other namespaces and unsupported expressions stay unresolved. Show hook, priority,
parent/default policy and incoming links instead of guessing a whole-path verdict.
Accept/log statements are not a proven final decision. Counters are packet/byte
reports since an unverified reset, not unique connections, clients or authentication
attempts. `nf_tables` compatibility views overlap native nftables; matching views
are not independent corroboration. An unknown backend is not silently classified.

Ruleset bounds: 192 KiB for nftables, 128 KiB for iptables, and 2,048 objects/text lines per source; 64 nft expressions
per rule, 2,048 set elements, 8,192 characters/128 tokens per iptables rule. Malformed
or excessive snapshots fail as an independent unavailable source; no successful
prefix becomes complete policy. Metadata and retained unknown expressions remain
literal administrator evidence, never executable commands.

## Fail2ban state and correspondence

Inspect up to eight validated literal jail names from a bounded server listing.
Each jail reads status, maxretry, findtime, bantime and action names through a narrow
getter allowlist. No action method, action script, ban/unban or configuration getter
that executes code is invoked. Status has a 32-KiB bound; settings/action names have
4-KiB bounds. A jail's reported identity must match the request. Preserve reported
counter/list disagreements and all original output in accepted snapshots.

Current settings explain the reported trigger policy, not a proven trigger for an
older ban. Lifetime counters are not boot-relative. Configured bantime is not actual
remaining lifetime: increments, overrides and restored/manual bans can differ.

Preview at most 128 reported banned entries, with up to eight same-address block
expression references each. Build one prefix index with capped shared references
before comparing bans, so shared large sets are not repeatedly parsed for each ban. A positive correspondence requires a source address or
recognized referenced nft set containing the entire reported address/prefix and an
explicit drop/reject expression. Negated sources, log/accept-only rules and names
alone do not establish correspondence. Preserve remaining rule conditions and set
references; this does not establish action ownership, chain reachability, effective
enforcement or who requested the ban. An eight-reference preview reports when its cap is reached. No supported match can mean missing sources,
unsupported constructs or an action problem; it does not prove an ineffective ban.
The program/jail report and human initiator are separate. Human initiator is Unknown;
independent human audit evidence is not collected or fabricated by this step.

## Retained history

Unit journal context uses a frozen boot/hour/day/explicit UTC period, optional
immutable boot filter and existing visible/system journal preference. Validate
root-UID unit records, or root PID-1/systemd records naming fail2ban.service, plus
boot, receipt bounds and unique cursors. Validate the complete captured response;
retain a 200-record tail and flag a 201st sentinel. Every retained original is
inspectable. Reports of Ban, Restore Ban, Unban and Found are observations, not
verified action success or distinct authentication failures. Known ban/unban/reban
action-execution errors are exposed as jail-wide historical context without guessing
an address or association with a current ban. Unknown messages remain.

Also inspect fixed `/var/log/fail2ban.log` and `.1` through a private isolated helper,
with no arbitrary path option. Walk directory descriptors with O_NOFOLLOW and root
ownership, reject world-writable directories, and require a single-link root-owned
regular file without group/world write. Group-writable log directories are accepted
for ordinary Ubuntu layouts; descriptors/file checks prevent symlink substitution.
O_NONBLOCK precedes file validation. Missing/denied/unsafe paths and invalid encoding
return fixed reader states without echoing exception contents. Read at most 32 KiB from the existing tail,
drop a leading partial line, retain the complete accepted tail with SHA-256 and
change-during-read metadata, and interpret at most 200 lines. Compressed/custom
rotations, syslog-only alternative targets and databases are not inspected.

File timestamps remain reported local text, without guessed UTC/DST/boot identity.
File tails are explicitly unfiltered by the selected UTC period, separately from
the journal query. Related-log navigation matches reported jail/address, not proven
causality or the current ban's lifetime. Identical/copied logs are not independent
corroboration. Root/kernel compromise can falsify every local source.

The shared collection budget is 20 seconds checked before each read; the last native
call can add its two-second capture deadline, excluding parsing/scheduling. Existing
8-MiB UI capture applies. On exhaustion, later sources report time_limit rather than
silently disappearing. Reads are sequential/non-atomic; no complete capture claim.

## Navigation and verification

Network opens Rules, Chains/defaults, Sets, Jails, Bans, Sources and Records. A jail
opens current thresholds, related logs and its reported bans. A ban opens actual
matching expressions and related retained messages. A chain opens its retained
rules. Original fields and Evidence pins preserve exact source/time context.
The existing serial cancellable modal lifecycle is shared with SSH: rapid window
replacement waits for cleanup, refresh drops the previous cache and failures do not
restore it as a new result. One firewall snapshot is cached in memory; a pin can
retain an older explicit selection. No preferences or diagnostic evidence are saved.

Synthetic acceptance covers dual-stack rules/sets/defaults, frontend/backend overlap,
conditional matches and negation, unknown constructs, absent/invalid/capped sources,
thresholds and unverified human attribution, log scope, getter validation and safe
file handling. Actual frontend tests cover matching-rule/log/original navigation,
Evidence, compact resize, cancellation and existing SSH regressions. CLI/TUI resource
scenarios now retain 419 nft rules under unchanged CPU/wall/RSS and aggregate deadlines (the initial delivery used 256).
Native/installed qualification adds the ninth `firewall` command contract; existing
Debian/Ubuntu package/security gates remain required. Live server validation remains
operator feedback, not a synthetic pass or a reason to modify production policy.

Primary references: [nftables semantics](https://netfilter.org/projects/nftables/manpage.html),
[nft JSON schema](https://manpages.debian.org/bookworm/libnftables1/libnftables-json.5.en.html),
[Fail2ban read commands](https://github.com/fail2ban/fail2ban/blob/master/man/fail2ban-client.1),
[Fail2ban status formatting](https://github.com/fail2ban/fail2ban/blob/master/fail2ban/client/beautifier.py).

## Reader corrections after 1.2.0

A reported 140,920-byte snapshot exceeded the original 128-KiB nft reader cap;
the same complete response normalized as 419 rules, 94 chains and two sets at
192 KiB. The nft-only cap is now 192 KiB, below the unchanged combined 256-KiB
stdout/stderr capture. Object/expression/set, command deadline and UI bounds stay
unchanged. Excessive snapshots report numeric actual/limit/unit metadata instead
of conflating a size limit with unsupported syntax. No partial policy is accepted.

Xtables resolves several program names to one nft/legacy multicall executable.
Keep the canonical trusted executable path, but explicitly preserve the selected
read-only catalog invocation name in argv[0]. The OS executes that verified path;
no symlink or PATH lookup is substituted. Only the four existing iptables/ip6tables
version/save names are allowed, never restore or an action provided by source data.
Completed command stderr is retained within the same combined capture bound and
shown as escaped original administrator evidence. A nonzero exit is independent
from parsing failure; root status alone does not prove kernel/namespace access.

Qualification installs nftables/iptables as disposable test-only tools, not package
runtime dependencies. Non-root readers may correctly report denied access; the
installed regression gate separately rejects multicall-dispatch failures.
