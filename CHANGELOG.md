# Changelog

## Unreleased — 1.0.2

- Generalize service troubleshooting across manager failure results, main-process
  exits/signals and common error messages, retaining unknown causes and messages.
- Open individual messages, surrounding context, a bounded investigation period
  and relevant current System/Network readings from the service view.
- Distinguish same, different and unverified reported invocation identities.
- Replace the active delivery plan with the owner-approved four-step order and
  explicit practical Network / possible attack / DDoS investigation requirements.

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
