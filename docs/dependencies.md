# Dependencies and installation scope

Faultlens's Linux CLI runs on Python 3.11+ without external Python packages.
The optional UserDock-style workspace uses Textual 8.2.8 and its exact wheel-hashed
closure in requirements-tui.txt. Install it in a project-specific virtual environment;
see [workspace setup](tui.md). Missing or unreviewed Textual leaves the CLI available.
No package is installed at application launch, and no recorder, database, daemon or
cloud service is added. The dependency is justified by actual UserDock navigation,
widgets, focus and headless testing rather than another custom terminal renderer.
See [third-party dependencies](third-party.md) for reviewed versions/licenses and the
advisory-check scope. Original Faultlens material is GPL-3.0-or-later; see
[LICENSE](../LICENSE) and [NOTICE](../NOTICE).

Native tools remain feature-specific and are never installed or enabled automatically.
Run with existing access; unavailable evidence does not trigger privilege escalation.

| Tool | Used by | Requirement |
| --- | --- | --- |
| journalctl | history, incidents, diagnose, previous-boot check | Needed for these journal features; visible records depend on permissions and retention |
| systemctl | status/check/health service observations and bounded failed-service details | Needed for these service-manager observations only |
| systemd-analyze | check --history merged journald configuration | Optional; uses portable cat-config without --tldr; output compatibility is checked at collection time |
| ss | network/security --sockets; owner reporting with --network-context | Optional numeric local TCP/UDP snapshot and reported owners; existing permissions/namespaces apply |
| ip | network/security --network-context; current workspace Network/Signals | Optional numeric addresses/link state and separate IPv4/IPv6 route entries; commonly provided with ss by iproute2 |
| atop | diagnose --atop-date | Optional replay tool; recordings must already exist; Faultlens does not install or enable a recorder |
| free, df | scripts/validate_local.py | Optional comparison tools; ordinary status reads procfs/statvfs directly |

On typical Debian/Ubuntu systems, the systemd tools are provided by the systemd
installation, free by procps, and df by coreutils. Package availability and service
configuration depend on the distribution. Inspect existing availability first;
there is no blanket installation command or need to install every optional tool.
Atop recording and rotation require a separately managed service; installing a tool
does not recreate past measurements. Do not change sampling without measuring overhead.

The initial network/security commands read fixed procfs counters directly and need
no additional tool or package. The optional --sockets flag additionally invokes ss for endpoint observations.
--network-context adds fixed ip address/route reads, three counter intervals and
permitted ss owner reporting when sockets are requested. The workspace enables
this context for current network sections. Missing iproute2 evidence does not
require installation just to pass a server test; other sources remain useful.
Effective firewall policy and external connectivity are not inspected.

Faultlens currently does not invoke sosreport, sar, nstat or nft. They are
excluded from dependency observations until an implemented feature needs them.
In particular, sosreport collection is not required and could gather substantially
more sensitive material than current Faultlens observations.

`dependency.*` reports trusted executable availability, not host health or full
feature readiness. The explanation identifies the feature and optional scope.
A missing optional tool is unavailable evidence, not a system security failure.
Journal availability also depends on existing access: default history/diagnosis reads
the visible set, and `--system-journal` explicitly selects accessible system journals.
The flag grants no permissions. See [source scope](architecture/phase-2-journal-scope.md).

## Candidate improvements

Prioritize better evidence quality before adding integrations:

- Explain exactly which feature is unavailable and why (permissions, unsupported
  version, missing tool or missing historical data), with a bounded capability probe.
- Extend the implemented bounded filename/sample gap hints with richer coverage
  provenance, preserving uncertainty about host/boot identity and incomplete input.
- Extend the implemented live/archive pstore readers with narrowly tested additional
  signatures and stronger event provenance.
- If local export is later requested, offer an explicit contents/destination preview
  with secure file creation. Preserve administrator originals; never redact or upload
  them automatically.

These extensions are proposals, not new installation requirements. The current
coverage/pstore scope is documented in [the milestone](architecture/phase-2-coverage-pstore.md)
and [archive support](architecture/phase-2-pstore-archive.md).
Each integration needs a documented threat model, resource budget and synthetic tests.

Firewall journal observations read existing kernel records through journalctl. They
do not invoke, require installing, enable or reconfigure UFW, nftables or iptables.
Existing logging/access controls determine whether relevant history is visible.

## Current login-session context

System/status can read existing local logind through `loginctl` and fall back to
`who --users`. Both are optional OS tools. No login manager/accounting service is
installed or enabled, no native session is controlled, and no DNS lookup or remote
query is requested. Missing or unsupported sources leave other System readings
available. See [session coverage and bounded collection](login-sessions.md).

## Debian package

The delivery is a downloadable `.deb`, with no project APT repository.
APT will resolve required distribution runtime dependencies from existing configured
package sources. CLI and the reviewed TUI must work without a user-managed virtual
environment. The build foundation now bundles the exact reviewed pure-Python wheel closure in a
private application directory, with APT declaring system Python >= 3.11. No user
virtual environment or runtime pip is needed. See [package qualification](debian-package.md);
additional owner-server testing is planned after package delivery.

Atop and other optional diagnostic tools will not be automatic installation
dependencies. Their packages can enable services, so recorder installation and policy
remain explicit administrator choices. No package script or application startup may
bootstrap dependencies with pip or downloads. See the
[package milestone](debian-package.md#automated-package-qualification) for acceptance gates.
