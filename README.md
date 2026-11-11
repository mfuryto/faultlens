# Faultlens

**Pre-release — Phase 1 CLI foundation.** Faultlens provides local, read-only Linux
system observations and dependency/logging checks. It is not yet an incident analyzer,
a TUI, a packaged distribution, or a supported production release.

The initial target is Debian/Ubuntu Server with Python 3.11+. No external Python
packages, telemetry, network service, database or daemon are required. `prompt_toolkit`
remains the preferred future TUI candidate; it is not installed by this foundation.

## Run from source

From a trusted checkout, as an ordinary user:

```sh
./bin/faultlens
./bin/faultlens status
./bin/faultlens status --json
./bin/faultlens status --sample-seconds 0.2
./bin/faultlens check
./bin/faultlens check --json
```

`python3 -m faultlens` is an equivalent entry point from the repository root. The
launcher can also be invoked by absolute path from another directory. No installation
or root access is required. Python source imports may create normal bytecode caches;
the launcher disables them. Faultlens does not save reports or change system settings.

Status covers sampled aggregate CPU, load, RAM/swap, root filesystem capacity,
cumulative per-device I/O and interface counters, visible process count, kernel/boot
information and the systemd manager state where available. `check` inspects optional
utilities, journal directory presence, visible prior boots, and journald/atop service
state. It never reads out raw log entries or claims that a directory proves recording.

Evidence can be sensitive even in summary form. Output stays on your terminal/stdout;
review it before manually redirecting or sharing it. No automatic exports or uploads
exist. Missing/denied/malformed sources are explicitly unavailable, not healthy zeros.
JSON includes units, source, confidence, explanations, thresholds and limitations.
CPU/network counters may reflect a host or namespace rather than cgroup limits.

For an optional local consistency check against trusted `free`, `df`, `uname`'s
kernel interface and the Linux boot clock:

```sh
python3 scripts/validate_local.py
python3 scripts/validate_local.py --json
```

The comparison prints only PASS/MISMATCH/UNAVAILABLE and fixed explanations, never
raw machine values. It saves nothing and does not run automatically in CI. Validation
exit codes are separate: 0 means all eight comparisons matched within documented
tolerances, 1 means a mismatch, 2 means incomplete/unsupported validation, and 130
means interrupted. A mismatch can reflect collection-time differences; a pass is
not proof of host health. See [measurement validation](docs/validation.md).

Exit codes: 0 means a report was rendered (including partial/unavailable observations),
1 means unsupported platform or collection/rendering failure, 2 means invalid arguments,
and 130 means interrupted collection. Inspect observation states for warnings or gaps;
exit 0 does not assert that the system is healthy. `health`, `network`, `security`,
`incidents`, `diagnose`, `history`, configuration changes and the TUI are not implemented.

## Develop and verify

Use only `staging` and `main`; PRs to main require the baseline, analysis and CodeQL
findings checks. Synthetic tests never collect diagnostics from the CI host.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/security_check.py
python3 scripts/benchmark.py --iterations 10
```

Security checks inspect tracked files and all locally reachable Git history. Stage new
files before running the tracked-file scan; fetch all refs before a publication audit.
No dependency installation is needed. Benchmark methodology and initial measurements
are in [resource benchmarks](docs/benchmarks.md).

Read [contributing](CONTRIBUTING.md), [private vulnerability reporting](SECURITY.md),
[product specification](docs/product-specification.md),
[Phase 1 decisions and limitations](docs/architecture/phase-1.md),
[threat model](docs/security/architecture.md), and
[repository controls](docs/security/hardening-status.md).

## Licensing

No license has been selected or granted. Do not assume permission to redistribute.
A license requires explicit owner approval before a licensed release.
