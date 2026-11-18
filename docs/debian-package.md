# Pre-release Debian package

The active delivery is a downloadable `.deb`, not a project APT repository. The
builder and isolated package tests are implemented; no release or tag is published.
The owner has one server. A second real-server/SSH test is a known qualification
limitation and does not block package engineering. Debian/Ubuntu containers are
installation/process tests, not a substitute for that missing field test.

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

Default snapshot versions use `0.1.0~dev0+git<TIMESTAMP>.<COMMIT>` and the commit's
reproducible build epoch. `--version`/`--epoch` support explicit test/source-archive
inputs; versions must retain the current pre-release identity. Existing artifacts
are never overwritten. Normalized timestamps/modes, root archive ownership, sorted
inputs and single-thread xz compression produce identical bytes for repeated builds
with the same inputs, version, epoch and toolchain. The artifact is published locally
only after successful archive construction, with its SHA-256 printed. This is not a
claim of reproducibility across every Python/dpkg/xz version or filesystem.

## Install and use a preview

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
APT repository exists. Future previews must use a newer version for normal upgrades.

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
2. Six installed CLI contracts, private frontend isolation, real workspace child
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

## Remaining delivery work

This is a tested build/install foundation, not production or public-release acceptance.
The owner-server package installation/SSH check remains to be performed. Real incident
and workload evidence, and the unavailable second real server, remain documented
qualification limits. Before a public release, review final package/contact/changelog
metadata, rerun dependency advisory checks and installed qualification, and provide
matching GPL corresponding source (including build/install scripts and dependency
provenance) with the artifact and checksum. No release publication is implied here.

Policy reference: [Debian Python Policy](https://www.debian.org/doc/packaging-manuals/python-policy/).
