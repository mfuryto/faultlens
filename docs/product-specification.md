# Faultlens
**Linux System Monitoring, Diagnostics & Incident Analysis**

## 1. Project overview

Faultlens is a lightweight, fully local Linux CLI/TUI application for real-time system monitoring, historical incident analysis, network security assessment, and explainable diagnostics.

The primary purpose is to provide Linux administrators with a clear understanding of:

- The current health and operational status of a Linux system.
- What is happening on the network, including suspicious activity and potential attacks.
- What happened before a system became unresponsive or required a forced reboot.
- Why the tool identifies a problem, including supporting evidence and technical explanations.
- What actions an administrator can take to investigate or resolve an issue.

Faultlens must prioritize existing Linux utilities, system logs, and established diagnostic tools rather than duplicating their functionality.

The project must remain lightweight, modular, transparent, and suitable for small VPS instances.

## 2. Core requirements

### 2.1 Platform and architecture

- Linux only, initially Ubuntu Server and Debian.
- Fully local operation.
- No cloud services, external collectors, telemetry, or central monitoring infrastructure.
- No web interface.
- Interactive terminal interface (TUI) inspired by Userdock.
- Full CLI functionality independent of the TUI.
- Python with `prompt_toolkit` is the preferred implementation.
- No permanently running Faultlens daemon unless a clearly documented requirement cannot be satisfied using existing Linux facilities.
- Existing system utilities and logs must be preferred over custom implementations.
- All source code, comments, logs, and documentation must be in English.

### 2.2 Resource efficiency

Faultlens must have minimal impact on the monitored system.

Initial performance targets:

- Normal CLI/TUI memory usage below 50 MB where practical.
- Minimal CPU usage during normal operation.
- No continuous packet capture by default.
- No unnecessary background polling.
- No dedicated database unless justified.
- Avoid redundant collection and storage of existing system information.
- Measure and document actual resource consumption.

Performance targets must be verified through testing rather than assumed.

## 3. Functional modules

### 3.1 System Status

Provide current system health and operational information:

- CPU usage and load.
- RAM and swap usage.
- Disk usage, I/O and filesystem health.
- Running processes and resource consumption.
- System uptime and boot information.
- Systemd service health.
- Kernel errors and warnings.
- Network interface status.
- Network throughput, packet errors and dropped packets.
- Active connections and socket statistics.
- Relevant hardware information where available.

The interface must clearly distinguish normal operation, warnings, critical conditions, and unavailable information.

### 3.2 Incident Analyzer

This is a critical project capability.

Faultlens must reconstruct events preceding unexpected system failures, hangs, service outages, and forced reboots.

Requirements:

- Analyze previous Linux boot sessions.
- Identify the last recorded system events before a reboot.
- Distinguish normal shutdowns from potentially unexpected shutdowns.
- Detect evidence of kernel panics, OOM events, disk failures, filesystem errors and service failures.
- Correlate historical CPU, RAM, disk, process and network activity.
- Construct chronological incident timelines.
- Identify likely causes when supported by evidence.
- Support investigation of multiple previous boot sessions.
- Explain missing evidence and limitations.

A key use case is a VPS that stops responding to ping and SSH and must be restarted through its provider's control panel.

Faultlens must provide the best possible reconstruction from locally preserved evidence, while explicitly acknowledging that a complete system freeze may prevent the final events from being written to disk.

### 3.3 Network and Security Analyzer

Provide current and historical assessment of:

- Network traffic and connection statistics.
- Possible DDoS activity.
- SYN flood and UDP flood indicators.
- Unusual connection rates.
- Port scanning indicators.
- SSH brute-force attempts.
- Authentication failures.
- Firewall events and blocked connections.
- Suspicious network activity.
- Network resource exhaustion.

Faultlens must distinguish between suspicious activity and confirmed attacks.

Historical security assessments must only be made when relevant data was actually recorded.

Avoid heavyweight intrusion detection dependencies by default. Optional integrations may be supported when justified.

### 3.4 Evidence Explorer

Every warning, incident and diagnostic conclusion must be explainable.

For each finding, provide:

1. **Observation:** What was detected?
2. **Evidence:** Which measurements or log entries support the finding?
3. **Source:** Where did the information originate?
4. **Reasoning:** Why was the condition classified this way?
5. **Thresholds:** Which rules or limits were applied?
6. **Confidence:** How certain is the conclusion?
7. **Limitations:** What information is missing?
8. **Recommendations:** What should the administrator investigate?

The user must be able to inspect original logs, measurements, and technical evidence directly from the TUI.

Never fabricate observations or present assumptions as confirmed facts.

## 4. Existing Linux tools and data sources

Prioritize integration with:

| Source | Purpose |
|---|---|
| `systemd-journald` | System, kernel and service history |
| `atop` | Historical process and resource measurements |
| `/proc` and `/sys` | Current system statistics |
| `systemctl` | Service health |
| `ss` | Socket and connection information |
| `ip` | Network interfaces and statistics |
| `nstat` | TCP/IP protocol counters |
| `nftables` | Firewall rules, counters and events |
| `pstore` | Persistent kernel crash information where supported |
| `sysstat` | Optional historical statistics |
| `sosreport` | Optional comprehensive diagnostic reports |

Existing tools must be treated as external dependencies or integrations, not copied into the project without appropriate license review.

Missing optional dependencies must not prevent unrelated Faultlens functions from operating.

## 5. Historical data preservation

Faultlens must provide a setup and verification function that checks:

- Whether journald persistent storage is enabled.
- Whether previous boot logs are available.
- Whether atop is installed and recording.
- Whether historical collection intervals are suitable.
- Whether relevant kernel crash information can be preserved.
- Whether sufficient disk space and retention settings are configured.
- Whether security-related events are being recorded.

Faultlens should provide safe configuration recommendations and request explicit confirmation before changing system settings.

Suggested initial atop sampling interval: 30 seconds, subject to resource testing.

Historical data retention must be configurable.

## 6. Terminal interface

Implement a keyboard-driven TUI inspired by Userdock.

Main navigation:

1. System Overview
2. System Health
3. Network Status
4. Security Analysis
5. Incident History
6. Diagnostics
7. Evidence Explorer
8. Settings

The interface must support:

- Keyboard navigation.
- Clear status indicators.
- Drill-down into findings.
- Historical timeline navigation.
- Detailed technical explanations.
- Viewing original log entries.
- Refreshing current status on demand.
- Safe operation over SSH.
- Graceful handling of missing tools and insufficient permissions.

CLI commands should include:

```bash
faultlens
faultlens status
faultlens health
faultlens network
faultlens security
faultlens incidents
faultlens diagnose --previous-boot
faultlens history --last 7d
faultlens check
```

These are proposed commands and may be refined during implementation.

## 7. Diagnostic classification

Faultlens must classify findings using evidence-based categories:

- **Confirmed:** Directly documented by reliable evidence.
- **Probable:** Multiple observations support the conclusion.
- **Possible:** Some indicators exist, but evidence is insufficient.
- **Unknown:** Available information does not support a reliable conclusion.

The classification must distinguish between a confirmed event and a confirmed root cause.

All findings must remain traceable to their original evidence.

## 8. Security and implementation quality

- Prefer read-only diagnostics.
- Require explicit confirmation for configuration changes.
- Avoid unnecessary root privileges.
- Validate external command execution and input handling.
- Handle potentially sensitive logs securely.
- Do not automatically expose diagnostic reports externally.
- Apply relevant OWASP ASVS 5.0 Level 2 principles where applicable.
- Document security assumptions and limitations.
- Include automated tests for diagnostic rules and evidence handling.
- Support reproducible testing using synthetic logs and recorded system data.

## 9. Development priorities

### Phase 1 — Foundation

- Establish repository structure.
- Define modular architecture.
- Implement CLI framework.
- Implement dependency and logging checks.
- Implement current system status.
- Establish resource usage benchmarks.

### Phase 2 — Historical diagnostics

- Integrate persistent journald history.
- Integrate atop historical measurements.
- Identify boot sessions and unexpected shutdowns.
- Build chronological incident reconstruction.
- Implement evidence-backed diagnostic rules.

### Phase 3 — Network and security

- Implement current network status.
- Analyze SSH authentication and firewall events.
- Add traffic anomaly detection using available historical data.
- Implement explainable security findings.

### Phase 4 — TUI and refinement

- Implement Userdock-style terminal interface.
- Add detailed incident and evidence views.
- Improve navigation and reporting.
- Test on small VPS configurations.
- Optimize memory, CPU and disk usage.
- Prepare documentation and initial release.

## 10. Initial development instruction

Before implementing major functionality:

1. Review the proposed architecture critically.
2. Identify existing open-source tools or libraries that could eliminate unnecessary custom code.
3. Verify the available Linux interfaces and their limitations.
4. Define module boundaries and dependency strategy.
5. Identify gaps in historical data preservation.
6. Establish measurable performance and reliability requirements.
7. Document architectural decisions and trade-offs.

Do not introduce a daemon, database, external service or heavyweight dependency without a documented technical justification.

**The defining principle of Faultlens is simple:**

*Observe the system, preserve useful evidence, explain what happened, and help administrators understand why — with minimal overhead and no external infrastructure.*