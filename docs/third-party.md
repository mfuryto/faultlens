# Optional frontend dependency review

The CLI has no external Python dependency. The UserDock-style workspace requires
Textual 8.2.8 and the complete wheel closure below. requirements-tui.txt pins exact
versions and SHA-256 wheel hashes, and installation uses --require-hashes plus
--only-binary=:all:. CI installs into a temporary virtual environment with read-only
repository token permissions; it does not execute source builds or unpinned actions.

| Package | Version | Upstream license |
| --- | --- | --- |
| textual | 8.2.8 | MIT |
| rich | 15.0.0 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| platformdirs | 4.14.5 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| markdown-it-py | 4.3.0 | MIT |
| mdit-py-plugins | 0.7.0 | MIT |
| mdurl | 0.1.2 | MIT |
| linkify-it-py | 2.2.0 | MIT |

Versions, hashes and license declarations were reviewed from the official PyPI wheels
and their dist-info license files. No upstream implementation is checked into the source tree. Release
`.deb` packages bundle these exact wheels privately, retaining their complete license
files and metadata. The builder checks the hashes before extraction; required notices
and the project GPL text are included. Distribution packages cannot independently
patch this private closure: Faultlens updates require a reviewed lock, advisory check,
rebuild and new package. See [package maintenance and qualification](debian-package.md). Faultlens original material is licensed under GPL-3.0-or-later;
see [LICENSE](../LICENSE) and [NOTICE](../NOTICE). This project grant does not
replace upstream licenses or remove their notice obligations.

On 2026-11-19, pip-audit 2.10.1 checked all nine exact requirements and reported no
known vulnerabilities or skipped packages. The [version 1.0 audit record](security/dependency-audit-1.0.0.json)
is bound to the requirements file SHA-256. This is a dated advisory check, not proof against unknown issues.
Dependency graph/Dependabot alerts remain relevant; automatic update PRs stay paused
under the main/staging-only branch policy. Updates must be reviewed, re-hashed,
audited and tested on staging rather than silently accepted by a version range.

Textual is justified by matching UserDock's actual tab/table/modal interaction and
using maintained focus/layout/testing primitives. It adds measurable startup and
memory cost: keep the CLI dependency-free, render bounded source batches, avoid
background polling and retain an explicit frontend resource budget. Optional Markdown
and syntax facilities are transitive dependencies, not permission to render diagnostic
source text as markup. The application uses literal Rich Text, disables developer
network/log/driver hooks and never exports a report automatically.

Primary references: [Textual](https://pypi.org/project/textual/8.2.8/),
[testing](https://textual.textualize.io/guide/testing/) and
[worker lifecycle](https://textual.textualize.io/guide/workers/).
