# Faultlens

**Local Linux troubleshooting, with a terminal workspace and CLI.**

Faultlens helps administrators investigate problems now, during a chosen period or
before a restart. It brings together system measurements, service state, journal
messages, existing Atop recordings and crash evidence, explaining what was observed
and what to investigate next. Findings link to the retained original evidence.

[![Security baseline](https://github.com/mfuryto/faultlens/actions/workflows/security-baseline.yml/badge.svg?branch=main)](https://github.com/mfuryto/faultlens/actions/workflows/security-baseline.yml)
[![CodeQL](https://github.com/mfuryto/faultlens/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/mfuryto/faultlens/actions/workflows/codeql.yml)

## Install

Download `faultlens_1.1.0_all.deb` from [Releases](https://github.com/mfuryto/faultlens/releases/latest), then install it:

```sh
sudo apt install ./faultlens_1.1.0_all.deb
```

APT installs Python when needed. The reviewed terminal frontend is included; no
virtual environment or pip setup is required. Debian 12 and Ubuntu 24.04 are the
automated package-test targets. Optional tools such as Atop are installed separately.

## Start

```sh
faultlens
```

Use Left/Right to change sections, Enter to open details, Esc to return, `r` to
refresh and `q` to quit. Data loads when you open a source section; preferences are
saved per user. See [commands and examples](docs/cli-reference.md) for CLI use.

## What to expect

- Current resource, service and network symptoms, with explanations and next steps.
- Bounded investigations of retained logs, recordings and supported crash fragments.
- Full local administrator evidence, with clear source coverage and uncertainty.

Faultlens runs locally and is read-only by default. It has no telemetry, cloud
service or daemon, and never elevates itself or changes server logging. Missing logs
are an unanswered question; a reported event does not establish its underlying cause.
This is a fault-investigation tool, not a comprehensive security or CVE scanner.

[User documentation](docs/index.md) · [Development](docs/development.md) ·
[Contributing](CONTRIBUTING.md) · [Report a vulnerability privately](SECURITY.md)

Licensed under [GPL-3.0-or-later](LICENSE). Bundled dependencies retain their
[upstream licenses](docs/third-party.md).
