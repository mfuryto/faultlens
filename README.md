# Faultlens

**Pre-release — planning and security foundation only.** No diagnostic application,
installable package, or supported release exists yet. This repository remains private.

Faultlens is a planned lightweight Linux CLI/TUI for local system monitoring,
incident reconstruction, and explainable security diagnostics, initially targeting
Debian and Ubuntu Server. Python is preferred; `prompt_toolkit` is a candidate,
not an installed dependency. Proposed commands in the specification are not available.

## Security principles

- Fully local runtime: no telemetry, cloud services, web interface, or automatic uploads.
- Read-only diagnostics and minimal privileges by default; explicit, scoped confirmation
  before any configuration change.
- Treat logs as sensitive, untrusted evidence. Distinguish observations, hypotheses,
  missing evidence, and confirmed causes.
- Use existing Linux tools through validated argument lists and bounded execution.
- Require justification before adding a daemon, database, service, or heavyweight dependency.

## Development

Python 3.11 or later and Git are sufficient for the baseline checks; no pip install
or live system collection is required:

```sh
python3 scripts/security_check.py
python3 -m unittest discover -s tests -v
```

The checks inspect tracked files and all locally reachable Git history. Fetch all
remote branches and tags before a pre-publication audit. CI uses a full checkout.
Do not run proposed diagnostic commands as root to test this foundation.

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), the
[product specification](docs/product-specification.md),
[security architecture](docs/security/architecture.md), and
[publication checklist](docs/security/pre-publication.md).

## Licensing

No license has been selected or granted. Do not assume permission to redistribute.
A license requires explicit owner approval before public release.
