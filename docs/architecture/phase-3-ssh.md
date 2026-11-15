# Phase 3: SSH journal observations and administrator evidence

Status: initial opt-in SSH milestone, pre-release. Findings describe recorded
reports, not proven attacks, full sessions, malicious identities or root causes.

```sh
./bin/faultlens diagnose --boot 0 --system-journal --search-ssh --json
./bin/faultlens diagnose --previous-boot --search-ssh
./bin/faultlens diagnose --boot 0 --show-evidence --json
```

## Fixed source and time scope

Boot selection uses the same validated scope-local listing and immutable ID as the
existing diagnosis. The additional fixed query selects `_UID=0`, `_TRANSPORT=syslog`
and one of `_COMM=sshd`, sshd-session or sshd-auth. Fields for the same key use journal
OR semantics; root UID, transport, boot ID and optional receipt-time bounds all apply
together. SYSLOG_IDENTIFIER or an application's copied text alone never suffices.
These are trusted journal producer constraints, not executable attestation. Root/kernel
compromise, imported/forwarded logs and unsupported logging arrangements remain limits.

The query honors --since-us and --until-us inclusively. Both are revalidated against
every returned record, including the sentinel. Unlike the existing --search-events
profiles, SSH search is narrowed by those bounds. No grep, user regex, arbitrary path,
extra daemon, package, sudo, key lookup or network connection is introduced.

At most 501 candidates are requested and 500 retained, with the existing two-second
subprocess deadline and 256 KiB combined output cap. Invalid sources, mixed boots or
unexpected bounds reject the whole SSH response, without a broader retry. Empty valid
queries do not prove absent authentication or complete access. SSH search can succeed
independently of the ordinary tail; its findings stay in `ssh_analysis`, separate
from main reconstruction, shutdown assessment, other searches and Atop pairing.

## Narrow rules

| Rule | Supported complete format | Interpretation |
| --- | --- | --- |
| ssh.password_failed | Failed password, optionally invalid user, numeric peer/port and ssh2 | Recorded password failure; not brute force |
| ssh.password_accepted | Accepted password with numeric peer/port and ssh2 | Recorded authentication acceptance; not proof of authorization or a complete session |
| ssh.invalid_user_report | Invalid user with numeric peer and port | Recorded invalid-user report; may overlap another report for the same connection |

Supported formats were checked against OpenSSH 9.2/9.8 auth reporting. Username tokens
are bounded; numeric IPv4/IPv6 addresses and ports 1–65535 are validated. A single
trailing newline and supported preauth suffixes are accepted. Extra text, multiline
injection, partial authentication, keys, PAM-specific variants and localized/other
formats remain unclassified. Counts describe reports, not distinct attempts or attacks.
An unclassified record is not declared benign. Root/non-root transports/names outside
the fixed profile are not searched, and no claim of full SSH coverage is made.

## Administrator visibility and terminal safety

This is an administrator tool: parsed usernames, peer addresses and ports are visible
in finding evidence. Every retained candidate, including unclassified/binary messages,
is inspectable in `records`, with original MESSAGE value, collected metadata and
original cursor. Identities are not masked, hashed or grouped away for privacy.
JSON text output escapes controls and non-ASCII characters; decoding JSON restores
the original content. Logs cannot execute ANSI/OSC commands on the terminal.

`--show-evidence` also exposes all retained ordinary journal records and candidates
from --search-events, without changing their filters or caps. Default summaries stay
concise; this is a presentation choice, not a privacy barrier. Only requested metadata
fields are collected; this view does not claim every possible journal field. Unsupported
text/binary representations remain available for inspection but do not become findings.
Non-finite JSON and nesting beyond 32 levels fail closed before rendering. Original
cursor values allow further inspection using existing local journal access.

No evidence is saved or uploaded automatically, and no extra access is granted.
Atop now has [administrator identity/source views](phase-3-atop-admin.md). Full local
visibility for [pstore](phase-3-pstore-admin.md) is now implemented; future TUI
integration remains work; the product requirement is explicit that final
administrator views must not impose privacy-based masking. Repository/CI fixtures
remain synthetic, independently of what an administrator may view locally.

## Verification and remaining scope

Synthetic tests exercise producer spoofing, parser signatures, identity preservation,
unsafe terminal text, binary/oversized analysis messages, caps/sentinels, time/boot/scope
consistency, independent failures and empty results without security claims. The benchmark
combines 500 SSH findings/records, 500 ordinary records and both 500-candidate filtered
queries with original evidence enabled. No real authentication events are generated.
Broader key/PAM methods, aggregate brute-force indicators, firewall events and stronger
source identity remain future phase 3 work. Supported-host native SSH detection still
requires target validation; a successful empty query is only a collection smoke test.

References: [OpenSSH 9.2 auth reporting](https://github.com/openssh/openssh-portable/blob/V_9_2_P1/auth.c),
[OpenSSH 9.8 auth reporting](https://github.com/openssh/openssh-portable/blob/V_9_8_P1/auth.c),
[journal trusted fields](https://www.freedesktop.org/software/systemd/man/253/systemd.journal-fields.html).
