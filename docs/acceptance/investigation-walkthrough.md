# Synthetic investigation walkthrough

This optional source-checkout aid makes the fault-investigation workflow visible
when a server has no usable incident messages. It runs the actual report interpreters
and Textual workspace against small invented in-memory records. It is not a native
server test, a monitoring mode or evidence of an incident on the operator's server.

No native diagnostic command, host evidence reader, preference load/save or external
service is used. No root access, installation, workload change or fault injection is
required. The TUI requires the same reviewed optional environment as normal Faultlens;
the readable CLI example works with system Python without Textual. Nothing is
downloaded by the launcher. No additional application dependency is introduced.

## Reported OOM kill

From the checkout, in the actual SSH terminal:

```sh
.venv/bin/python scripts/investigation_demo.py --scenario oom
```

The persistent **SYNTHETIC DEMO** banner identifies the session. History contains one
invented previous boot. Enter opens its context; **Investigate this boot** opens
Diagnostics. Select the OOM finding and open **Records** to inspect the original
invented message, or use `e` for original fields. Evidence retains the same source
references. The example must explain:

- At `2026-01-01T00:01:00Z`, the invented kernel record reports killing PID 42,
  `synthetic-demo-worker`, because of a memory shortage or limit.
- That report can explain the process stopping. It does not establish why memory
  ran out, a leak, a host crash or the underlying cause of an outage.
- Inspecting memory pressure and resource limits around the event is a proportionate
  next investigation. No configuration repair is automatically selected or executed.
- The same message can appear in both tail and broader-search results. These are
  repeated views of one report, not independent OOM incidents or corroboration.
- The final retained heartbeat does not establish what happened afterward. Root
  cause and complete shutdown remain unverified.

Resize, switch tabs and open/close evidence dialogs using the normal controls. Other
source sections explicitly say their data is not modeled; opening them cannot query
the real server. Refresh regenerates synthetic data only. Settings changes are
session-only; selecting another boot/time can correctly leave the demo with no
matching retained data. Atop and crash sources have no modeled evidence.

For a readable CLI comparison:

```sh
python3 scripts/investigation_demo.py --scenario oom --cli
```

## Readable unmatched data versus unavailable logs

Run these separately, quitting between TUI sessions:

```sh
.venv/bin/python scripts/investigation_demo.py --scenario no-match
.venv/bin/python scripts/investigation_demo.py --scenario unavailable
```

Open Diagnostics with Right from History. Compare:

| Scenario | Required explanation |
| --- | --- |
| `no-match` | Invented heartbeat records were readable, but no supported fault pattern matched. The last retained message remains available. The server is not declared healthy or error-free |
| `unavailable` | The invented boot is listed, but its journal reads fail. The selected evidence could not be assessed; absence of faults is not established |

Both retain Unknown root cause. The unavailable case must never use the readable
no-match wording. These CLI comparisons exercise the same report interpretation:

```sh
python3 scripts/investigation_demo.py --scenario no-match --cli
python3 scripts/investigation_demo.py --scenario unavailable --cli
```

The timestamps and boot identities are invented. Report generation time is not an
event time. Any investigative commands shown by the shared presentation are examples
of follow-up for real investigations, not commands the demo executes or instructions
to apply a repair to the host.

## Record the result

Report whether the OOM explanation, original-message path, no-match/unavailable
distinction and navigation are understandable, or state the exact confusing screen.
No host logs are needed to give that feedback. Record this as **synthetic walkthrough
acceptance**, separate from real incident reconstruction, native collection,
preference persistence, workload impact and another server's acceptance in the
[server qualification record](server-qualification.md).

The normal application remains `.venv/bin/python bin/faultlens tui`. Its saved
preferences and actual accessible evidence are independent from this demonstration.
