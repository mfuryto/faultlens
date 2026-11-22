# Debian package and release verification

Version 1.1.0 is distributed as a downloadable `.deb`, with corresponding source and
checksums, through [GitHub Releases](https://github.com/mfuryto/faultlens/releases).
There is no project APT repository. Additional Ubuntu-server testing is planned by
the owner after receiving the package; it is follow-up verification, not a functional
limitation or release blocker. Container results describe installation/process tests.

## Runtime and dependencies

The `Architecture: all` archive contains pure Python and data only:

- `/usr/bin/faultlens` links to the private launcher under `/usr/share/faultlens/bin`.
  With no arguments it opens the primary workspace; `tui` remains an alias.
- `/usr/share/faultlens/faultlens` contains allowlisted application modules.
- `/usr/share/faultlens/vendor` contains the exact nine universal wheels from
  `requirements-tui.txt`, including their original metadata and license files.
- `/usr/share/doc/faultlens` contains project/license/dependency notices and a
  source/wheel SHA-256 build manifest. The manifest records actual copied input
  bytes; an observed Git revision alone does not attest source cleanliness.

APT resolves `Depends: python3 (>= 3.11)` through existing configured package sources.
It may download Python and its distribution dependencies if missing. The frontend is
already in the archive: installation and launch never run pip or fetch Python packages.
There is no user virtual environment, bundled Python interpreter, global Python-module
installation, maintainer script, daemon, service activation, log-policy change or
permission grant. Optional tools such as Atop are outside `Depends` and `Recommends`.
Their existing installation and recording policy remain administrator decisions.

The fixed `/usr/bin/python3 -IS` launcher (isolated, no site initialization) ignores
Python-path/user-site injection and system site packages, and
adds only the private application/vendor paths. The workspace's child CLI launcher
uses the same private runtime. Suggested Faultlens commands use the public launcher
when installed; a damaged or unreviewed frontend calls for reinstalling a verified
`.deb`, not installing packages into the system interpreter with pip.

Bundling is necessary to supply the reviewed Textual version consistently rather than
assuming every distribution provides it. These private libraries are not independently
updated by distribution `python3-textual` packages. Their security maintenance belongs
to Faultlens: review advisory results, update the complete hash lock, rebuild, retest
and distribute a new version when required. See [third-party review](third-party.md).

## Build from a trusted source checkout

Build as the non-root checkout owner using Python 3.11+, `dpkg-deb` and the reviewed
wheel inputs. A virtual environment/pip is needed only to obtain those build inputs:

```sh
python3 -m venv /tmp/faultlens-package-inputs
/tmp/faultlens-package-inputs/bin/python -m pip download --require-hashes --only-binary=:all: --dest /tmp/faultlens-package-wheels -r requirements-tui.txt
python3 scripts/build_deb.py --wheelhouse /tmp/faultlens-package-wheels --output-dir dist/preview-1
```

Use an empty output directory. After the wheel download, the builder works offline
with only the standard library and `dpkg-deb`; it does not execute upstream build code.
It verifies every wheel hash, universal/purelib layout and safe archive paths, then
rechecks the frozen bytes before extraction. Missing, extra, changed or symlinked
wheels fail. Only `packaging/debian/application-files.txt` application sources and
explicit packaging/docs inputs are exported: ignored environments, credentials,
local modules, collected evidence and the Git directory are not package inputs.
The security policy requires this allowlist to match tracked application modules.

Stable versions match the application version (`1.1.0`). Development snapshots use
the source version and commit timestamp/hash. `--version`, `--epoch` and
`--source-revision` support explicit source-archive rebuild inputs; versions must
retain the application identity. Release qualification upgrades an internal RC
package to the stable package. Existing artifacts
are never overwritten. Normalized timestamps/modes, root archive ownership, sorted
inputs and single-thread xz compression produce identical bytes for repeated builds
with the same inputs, version, epoch and toolchain. The artifact is published locally
only after successful archive construction, with its SHA-256 printed. This is not a
claim of reproducibility across every Python/dpkg/xz version or filesystem.

## Install and use

After inspecting the printed artifact path/hash, install the single archive from the
fresh output directory (select the exact printed filename if there are several):

```sh
sudo apt install ./dist/preview-1/faultlens_*.deb
faultlens
faultlens status
faultlens investigate --mode now
```

Installation needs package-manager privileges; launching Faultlens does not. Source
permissions/retention still control available evidence. No recording or wider access
is configured by installing the application. Installing optional distribution tools
separately can have their own service side effects; they are not installed by this
package. Keep the previous `.deb` if a manual rollback is needed; do not assume an
APT repository exists. Future updates must use a newer version for normal upgrades.

`sudo apt remove faultlens` or `sudo apt purge faultlens` removes package-managed files.
User preferences and locally collected evidence are outside the package manifest and
are preserved. Removal does not authorize deleting user data or changing logging.

## Automated package qualification

```sh
python3 scripts/package_acceptance.py --target debian-12 --wheelhouse /tmp/faultlens-package-wheels
python3 scripts/package_acceptance.py --target ubuntu-24.04 --wheelhouse /tmp/faultlens-package-wheels
```

These developer tests require Docker; installed Faultlens does not. Each target uses
a digest-pinned official clean base, no host installation, no exposed ports and a
new container-ID file. Only that created container is removed on exit/interruption.
APT uses its normal privileges inside a writable disposable filesystem: five
package-manager capabilities are granted after dropping all others, with no-new-
privileges, CPU/memory/process bounds and read-only package/test-input mounts.
Application checks run as UID 65534 and assert zero effective capabilities. The
network is disconnected before any application checks or upgrade/removal.

The gate verifies:

1. Identical bytes from two builds and failure to install with missing offline
   dependencies, followed by normal APT dependency resolution on a Python-free base.
2. Seven installed CLI contracts, including service investigation, private frontend isolation, real workspace child
   collection and no-argument PTY startup, navigation/resize, quit/Ctrl-C restoration.
3. All 28 synthetic benchmark scenarios (two iterations) and 21 one-CPU constrained
   profiles against installed application modules, preserving the existing CPU,
   wall/memory and 25/30-second aggregate budgets. Only the existing fixture/driver
   code is mounted under `/source`; no source-checkout application is mounted there.
   Prepared source-checked bytecode remains explicit, as in source qualification.
4. Disconnected-network local-file upgrade and purge preserving preferences and a
   synthetic user evidence marker. No live logs or originals are printed by the tests.

CI adds independent `package` matrix jobs for both targets, alongside unchanged
baseline/platform/resource gates. The workflow remains read-only with SHA-pinned
checkout and no artifact publication. Native package tests use current signed APT
indexes, so runtime dependency patch versions may change; report the actual Python
version separately from reproducible application-archive inputs.

## Release source and checksum verification

The release assets are `faultlens_1.1.0_all.deb`, `faultlens-1.1.0-source.tar.gz`,
`release.json` and `SHA256SUMS`. Download them from the same release. Run
`sha256sum --check SHA256SUMS` in that directory before installation. Checksums detect
corruption; obtain both assets and checksums through the trusted release page.

The source archive contains the exact committed tree, build scripts and reviewed
wheels. `REBUILD.txt` supplies an offline build command with the exact version, epoch
and revision. Release preparation rebuilds that source archive and requires the
resulting `.deb` to match byte for byte. See [development/release procedures](development.md).

For final-asset qualification, `scripts/package_acceptance.py` accepts `--artifact`
with the `.deb` path. The gate tests installing the RC and upgrading to that exact
stable artifact, runs installed resource checks, then removes it while preserving
user files. No server installation is performed by the release scripts.

Field follow-up on the owner's additional Ubuntu server is planned. The version 1.0
scope, source bounds and current qualification evidence are recorded in
[release readiness](release-readiness.md); container tests do not claim whole-server
health or detector accuracy.

Policy reference: [Debian Python Policy](https://www.debian.org/doc/packaging-manuals/python-policy/).
