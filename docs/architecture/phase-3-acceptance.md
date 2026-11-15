# Phase 3 implementation and acceptance

This records the bounded Phase 3 CLI scope. The current optional frontend and its
dependencies are reviewed in [corrected frontend acceptance](phase-4-acceptance.md)
and [stabilization](../stabilization.md), superseding earlier UI assumptions.

Reviewed: 2026-11-15. The four Phase 3 CLI priorities are implemented within the
bounded source contracts below. Faultlens remains pre-release; this is not a claim
of complete intrusion detection, production deployment acceptance or completion of
the broader product specification. Phase 4 TUI/refinement remains separate.

## Delivery map

| Phase 3 priority | Delivered behavior | Boundary |
| --- | --- | --- |
| Current network status | Interface throughput/error/drop deltas, namespace TCP indicators, IPv4 UDP counters, optional TCP/UDP socket states/endpoints/queues and state counts | Current network namespace and existing permissions; no link topology, owner enumeration, remote reachability test or firewall policy inspection |
| SSH authentication and firewall events | Original supported root/syslog SSH reports, UFW-labelled kernel packet context, filtered timelines, repeated-failure and packet-pattern indicators | Selected boot and requested receipt bounds; narrow signatures, logging-policy/candidate caps and unknown final firewall verdict |
| Traffic anomalies using available historical data | Interval-normalized recorded interface and protocol rates compared with a short contiguous Atop baseline | Explicit --atop-date plus --atop-extended; no invented history, host/boot attribution or long-term model |
| Explainable security findings | Observation, evidence/source indices, reasoning, exact thresholds, Possible confidence, limitations and recommendations in text/JSON | No attack/root-cause upgrade, automatic response, privilege escalation or external exposure |

Earlier milestone documents describe their original scope. This review supersedes
statements that these four priorities remain wholly unimplemented; their collection
limits still apply. See [counters](phase-3-network.md), [sockets](phase-3-sockets.md),
[SSH](phase-3-ssh.md), [firewall logs](phase-3-firewall.md), and
[extended Atop](phase-2-atop-extended.md).

## Current UDP counters

`network` and `security` also read `/proc/net/snmp` twice through the existing bounded
source reader. Strict paired-column validation selects IPv4 UDP InDatagrams,
OutDatagrams, NoPorts, InErrors, RcvbufErrors and SndbufErrors. Missing/decreasing
counters are unavailable, never negative rates. InErrors/receive-buffer/send-buffer
error growth emits Confirmed counter observations, with attack/cause Unknown.
These counters overlap and do not prove distinct dropped packets or resource
exhaustion. IPv6 UDP counters are outside this adapter. Unrelated interface/TCP
observations survive UDP-source failure. No tool or Python dependency is added.
Unrelated TCP MaxConn=-1 is accepted as the dynamic-limit sentinel, not treated as
a negative UDP counter; see [RFC 1213](https://www.rfc-editor.org/rfc/rfc1213.html).
The [kernel counter documentation](https://docs.kernel.org/networking/snmp_counter.html)
explains why counter interpretation must respect protocol and aggregation semantics.

## Derived log indicators

`diagnose` derives `security_analysis` from successfully validated optional sources,
without issuing additional queries. Windows use boot-local monotonic receipt times,
not wall-clock deltas. Numeric addresses are canonicalized for grouping; original
addresses, usernames, messages and cursors remain visible in source evidence.

| Rule | Exact heuristic | Interpretation |
| --- | --- | --- |
| security.ssh_failure_burst | At least 10 failed-password reports from one reported numeric peer in an inclusive 300-second window within one boot | Possible password-guessing indicator; accepted-password and invalid-user-only reports are not counted |
| security.port_scan_indicator | At least 10 distinct reported destination ports within an inclusive 60-second window, grouped by boot, protocol, source and destination | Possible multi-port probing; TCP and UDP are separate, including legitimate outbound activity |
| security.udp_report_burst | At least 100 supported UDP packet reports within an inclusive 60-second window for one boot/source/destination | Possible traffic burst, not a measured UDP flood or distinct-packet count |

One strongest window per group/rule is reported, with earliest ties retained. Scan
windows maximize distinct destination ports rather than total log count. No
cross-boot or cross-source joining occurs. These are fixed investigation
heuristics, not empirically calibrated probabilities. Retransmissions, duplicate
logging rules, NAT/proxies, testing and normal administration can meet thresholds.
The tool never blocks a peer or claims that a firewall log proves a blocked connection.

## Historical rate anomalies

`security.historical_traffic_anomaly` requires five preceding contiguous non-RESET
samples for the same named series, then a sixth comparable sample. Every count is
already an Atop interval count; it is divided by that sample's own interval, never
differenced again. Samples are contiguous only when the next end time minus the
previous end time equals the next interval. RESET, gaps/overlaps or missing series
clear the relevant baseline. No missing interval is filled with zero.

The current rate must strictly exceed five times the median of the previous five
rates and meet the following absolute floor:

| Series | Minimum per second |
| --- | ---: |
| Per-interface received bytes | 100000 bytes/s |
| Per-interface received packets, protocol TCP input segments, UDP input datagrams | 100 events/s |
| Protocol active/passive TCP opens, TCP retransmitted segments | 10 events/s |
| Per-interface receive errors/drops, protocol UDP input errors | 1 event/s |

These thresholds identify a change relative to available data, not a capacity
limit, unusual behavior for every host, SYN/UDP flood, distributed attack, malicious
client or cause of a freeze. DDoS distribution cannot be established from namespace
aggregates. Workload shifts can be legitimate; virtual layers can double-count.
Recorded connection-open rates are not counts of unique clients or sessions. Source
samples and replay lines remain available, indexed by sample_index and output hash.

The existing replay window is 30 minutes around the last selected journal record,
with at most 256 samples and the native replay byte/time bounds. At the common
600-second recording interval, this window normally cannot supply six samples;
`insufficient_comparable_history` is explicit. Faultlens does not silently widen the
window, change recorder settings or create historical data. Existing higher-frequency
recordings may support comparison. Recorder tuning requires a separately measured,
explicit administrator decision.

## Availability, bounds and administrator evidence

Source states distinguish not requested, unavailable, available and partial evidence.
`historical_comparison.state` separately explains when no comparable baseline exists.
A source that returns no supported events can be available without proving that no
event occurred. Independent SSH/firewall patterns survive ordinary-tail collection
failure. Atop still follows its existing ordinary-journal window dependency.

At most 32 derived findings are rendered in deterministic log-then-traffic order;
matching_indicators counts all matches and findings_truncated is explicit. Original
source evidence is retained within its existing collection bounds; this cap is not
privacy redaction. Evidence links use source_analysis/candidate_indices for logs and
sample_index/baseline_sample_indices/output_sha256 for recordings. Do not interpret
array indices as global journal positions. Existing boot/cursor and original-content
views remain intact. Neither log windows nor recording samples establish continuous
coverage, input authenticity or independent corroboration.

## Verification and remaining release acceptance

Run as the checkout owner without root:

```sh
python3 -m unittest discover -s tests -q
python3 scripts/security_check.py
python3 scripts/benchmark.py --iterations 10
```

Invented acceptance data combines both 500-candidate log sources, six contiguous
recorded network samples, 32 interfaces, derived findings and the explicit finding
cap. Tests exercise thresholds, inclusive windows, distinct-port selection, source
independence, resets/gaps/missing series, interval normalization, original evidence,
text/JSON explanations and unknown attack/cause. Fresh-process resource regression
includes this integrated path; no live traffic, failed-login attempts, packet
capture or firewall changes are generated by tests.

Native read-only smoke checks validate accessible source formats only. Supported
Debian/Ubuntu release deployment tests, small-VPS load testing, detector calibration
against labeled sanitized datasets, additional authentication/firewall formats,
IPv6 UDP counters, owner/topology visibility and richer sustained baselines remain
release/refinement work. None is silently presented as implemented. Missing sources
or absent matches must never produce a security all-clear. No administrative GitHub
settings or license changes are required by this phase.
