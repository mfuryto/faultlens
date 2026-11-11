# Local measurement consistency checks

Run on the Linux host whose results you want to verify, as an ordinary user:

```sh
python3 scripts/validate_local.py
python3 scripts/validate_local.py --json
```

This is an opt-in development validation tool, not an incident diagnosis. It performs
read-only collection and reference queries in memory; output contains only fixed
metric names, comparison states and limitations. No raw host values, device names,
logs, addresses, reports or evidence files are printed, saved or uploaded. The regular
CI suite uses invented references and sources; it never invokes live validation.

The reference tools are optional, resolved through the same root-owned trusted-path
policy as the application, and invoked with fixed argv, a controlled environment, a
two-second deadline and a 256 KiB combined output limit. `free --bytes` and GNU
`df --block-size=1 --output=size,used,avail,pcent /` are supported. Missing tools,
nonzero exits, timeouts and unsupported layouts yield UNAVAILABLE, never a false PASS.

| Observation | Independent entry point / comparison | Tolerance |
| --- | --- | --- |
| memory.total | free byte total | exact |
| memory.used | free total and available byte fields | 2 percentage points |
| swap.total | free swap byte total | exact |
| filesystem.root.total | df total bytes | exact |
| filesystem.root.used | df used / total bytes | 1 percentage point |
| filesystem.root.user_used | df displayed use percentage | 1.01 percentage points |
| system.kernel_release | uname kernel interface | exact |
| system.uptime | CLOCK_BOOTTIME | elapsed validation collection time + 0.1 seconds |

Memory and disk values can change between reads. The tolerances handle ordinary
short-term movement; a busy host or a resize can still cause a mismatch. Do not
silently widen tolerances to hide persistent differences. The references ultimately
share the kernel's accounting, so agreement does not prove the kernel is truthful.
CPU interval usage, load, process counts, network/I/O counters and journal history
are explicitly outside this reference comparison. Synthetic parser tests cover their
semantics, but they are not claimed as independently live-validated measurements.

## Filesystem denominator

The existing `filesystem.root.used` field preserves its meaning: allocated blocks as
a percentage of all blocks. Reserved free blocks are included in total capacity but
unavailable to ordinary users. The additional `filesystem.root.user_used` field uses
allocated / (allocated + user-available) space. It can therefore be higher than the
original field. GNU df rounds its displayed percentage upward to whole percent;
Faultlens displays two decimal places. JSON sources and limitations disclose this.

For an invented filesystem with 1,000 blocks, 400 free and 350 available to users,
the allocated percentage is 60%, while user-capacity use is about 63.16%; df displays
64%. Warning/critical classification uses the unrounded ratio. A value rounded for
display can land on a threshold without crossing it in the underlying measurement.

## Results and exit codes

- PASS: the named comparison matched within its tolerance.
- MISMATCH: evidence was present but differed; inspect locally and repeat.
- UNAVAILABLE: missing or invalid reference/observation; no comparison was established.

Exit 0 requires all eight comparisons to pass. Exit 1 indicates at least one mismatch;
exit 2 indicates incomplete or unsupported validation without a mismatch. Interrupted
collection exits 130. Exit 0 does not attest to system health or complete correctness.
The ordinary status/check CLI retains its separate documented exit-code contract.

## Development verification — 2026-11-11

All eight opt-in comparisons passed on the development Linux environment. Raw data
was withheld, not committed as a fixture. This does not verify the user's machine,
all supported Debian/Ubuntu versions, resource-constrained VPS hosts or containers.
Run this command on each target to establish its own consistency evidence.

Boot-history collection now explicitly requests `--no-legend` so journal table headers
cannot be mistaken for malformed boot records. Empty CPU input fails with ValueError.
Synthetic regression tests cover reserved blocks, threshold boundaries, reference
formats, missing tools and real mismatches. No dependencies or privilege requirements
were added; free and df are optional validation integrations.

References: [GNU df](https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html),
[reserved filesystem space](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html),
and [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html).
