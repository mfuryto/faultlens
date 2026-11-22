# Changelog

## Unreleased — 1.1.1.dev0

- Add paged SSH authentication statistics for boot/hour/day/selected periods, with
  explicit outcome counts, username/peer/time groups and original-record navigation
  in CLI and Network. Missing sources and bounded scans retain honest coverage.

- Accept native ss owner-column padding while preserving original rows and all
  collection bounds; reject unexpected controls and trailing non-padding fields.
- Assess addresses/routes independently from failed socket-owner/process sources,
  and explain missing tools, failed commands and rejected output in source views.
- Show the complete literal service message in the Evidence selection preview,
  rather than interpreting a single message as a list of characters.
- Return selections pinned from Evidence to the retained inquiry or last source,
  instead of linking back to Evidence itself. Existing pinned origins are preserved.

## 1.1.0 — 2026-11-22

- Investigate general system-service failures through reported results, exits/signals,
  concrete messages, surrounding logs and bounded follow-up periods.
- Inspect current process CPU/RSS, reported system-service associations and separate
  filesystem space/inode pressure with explicit partial/unavailable coverage.
- Add practical Network investigation: three short intervals, extended TCP/IPv6 UDP
  counters, local addresses/link state/routes and permitted socket owner/service context.
- Explain network pressure and possible scan/authentication/traffic patterns with
  actual peers/ports, alternatives and original records; attack/root cause remain unverified.
- Follow History report examples into a selected period, reuse inquiry findings in
  Signals and pin exact Evidence selections across tab visits and refreshes.
- Retain original query/partition provenance, explicit service/peer navigation subjects,
  cached source-access explanations and compatible saved user preferences.

Existing read-only defaults, local evidence handling, dependency locks and resource
budgets are preserved. No daemon, telemetry, automatic repair, capture or blocking.

## 1.0.1 — 2026-11-22

- Open failed service rows to inspect current system-manager state and retained
  current-boot unit messages without leaving the terminal workspace.
- Explain supported AppArmor parser/include and loader errors with original messages,
  source references and cautious next steps; keep all unclassified messages readable.
- Add `faultlens service --unit NAME.service` with readable, detailed and JSON output.

## 1.0.0 — 2026-11-19

Initial release of the local Linux troubleshooting workspace and CLI.

- Investigate problems now, a selected period across restarts, or events before restart.
- Review current resources, failed services, networks, sockets and reported login sessions.
- Inspect bounded journal findings, original records, existing Atop data and supported
  live/archived pstore fragments with explicit source limits and unknown causes.
- Navigate a keyboard-driven terminal interface with automatic source loading,
  readable explanations, saved per-user preferences and technical evidence details.
- Install a `.deb` with a private reviewed frontend and ordinary APT Python dependency
  resolution, without pip or virtual-environment setup on the target server.
- Provide reproducible source/package bundles, checksums, offline source reconstruction
  and isolated Debian/Ubuntu install, resource, upgrade and removal qualification.

No telemetry, daemon, automatic recording, configuration changes or privilege grants.
Whole-host security/CVE auditing and automatic repair are outside this release.
