# Development and releases

Use only `staging` and `main`. Develop on staging and merge a reviewed PR after all
security, platform and package checks pass. Keep root access out of development
checks; do not change Git trust or ownership to bypass an error. Read
[CONTRIBUTING.md](../CONTRIBUTING.md) before changing collectors or source boundaries.

## Source checkout

Linux and Python 3.11+ are required. The CLI uses the standard library; the terminal
workspace uses the exact reviewed frontend closure:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-tui.txt
.venv/bin/python bin/faultlens
```

## Verify changes

```sh
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/python scripts/security_check.py
.venv/bin/python scripts/benchmark.py --iterations 10
.venv/bin/python scripts/vps_acceptance.py --iterations 3
```

Use [server_check](server-check.md) for combined source-checkout tests. It does not
validate an installed package instead of the checkout. Tests use synthetic evidence;
never add real logs, credentials, host identifiers or reports to fixtures or Git.
Generated binaries, wheels and environments remain ignored. Preserve meaningful
acceptance records and architecture history; keep the README focused on using the tool.

## Package and release qualification

See [package qualification](debian-package.md) for offline builds and disposable APT
targets. Existing source and installed resource budgets are unchanged. Docker is a
maintainer test prerequisite, not a Faultlens dependency.

A release is built from a clean, committed stable revision and the reviewed wheel
directory. This example rebuilds the published 1.1.0 tag; a new release uses its
verified stable main commit rather than a development version:

```sh
python3 scripts/build_release.py --ref v1.1.0 --wheelhouse /tmp/faultlens-platform-wheels --output-dir dist/v1.1.0
```

The bundle contains the `.deb`, complete corresponding source with exact dependency
wheels, `release.json` and `SHA256SUMS`. Its source archive is rebuilt offline and the
resulting `.deb` must match byte for byte. Output directories are never overwritten.
`REBUILD.txt` in the archive supplies the exact version/epoch/revision arguments;
Python 3.11+ and a compatible `dpkg-deb` toolchain are still required to rebuild.

Before publishing: refresh the dependency advisory report for the exact lock, run
all source/platform/package checks, qualify the final artifact on both target images,
verify required main checks on the publication commit, and inspect the final diff.
Tag only that verified commit. Upload assets to a draft, download and check their
hashes, then publish after explicit owner authorization. The owner authorized version 1.1.0 publication on 2026-11-22, including the combined
service, process/storage, network and inquiry/evidence improvements. Future publication requires
owner authorization and always uses the repository's ordinary GitHub Releases. No automatic publish workflow
or project APT repository is installed.
