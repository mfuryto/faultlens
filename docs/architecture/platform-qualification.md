# Milestone 3 — reproducible platform qualification

Design recorded before implementation, 2026-11-16. The owner requests continued work
on the ordered delivery plan. Milestones 1/2 have implementation and synthetic tests;
operator usefulness and real SSH/server acceptance remain open.

The first qualification candidates are Debian 12/Python 3.11 and Ubuntu 24.04/Python
3.12 on Linux x86-64. These are exact test targets, not production-support claims.
Ubuntu uses the existing hosted CI runner. Debian uses the reviewed cached official
Python image pinned by immutable digest. Containers share a host kernel and do not
establish booted-server, service-manager, remote-SSH or workload qualification.

Extend the existing constrained baseline with explicit native CLI contract checks on
Ubuntu, and network-disabled/read-only/non-root Debian checks before and after the
hash-locked optional frontend is installed. Run the complete existing test suite in
Debian as well. Prepare wheel downloads on the CI host; install offline in the Debian
temporary environment. No package is installed on an operator server, no new action
or application dependency is introduced, and token permissions remain read-only.

Native checks validate current measurements, graceful missing service/journal/socket
tools, structured result contracts and unavailable-log wording. Native diagnostic
content remains in memory; stdout contains only platform identifiers, source states
and contract results. No hostnames, addresses, logs or generated reports are committed
or uploaded as artifacts. Full administrator evidence remains available through the
ordinary CLI/TUI; this checker reports verification status only.

The image is pulled only by an explicit pinned CI preparation command. The checker
uses --pull=never, network none, read-only source/root, dropped capabilities, no-new-
privileges, a non-root UID and bounded memory/CPU/process/tmpfs limits. It never mounts
the Docker socket or system evidence directories. Existing strict workflow/action/
permission validation is extended to the exact reviewed commands, not relaxed.

Record actual environments and results separately from remaining acceptance: ordinary
and existing administrator access over real SSH, small VPS workload impact, terminal
navigation and a materially different second server. Never mark those gates passed
from containers or CI alone. No release/tag publication is part of this delivery.

## Reproduce the developer check

Use a trusted checkout as its non-root owner on a development host with an already
available Docker service. Do not install/start Docker on an operator server for this
check. Prepare the pinned image and reviewed wheels explicitly:

```sh
python3 -m venv /tmp/faultlens-platform-host
/tmp/faultlens-platform-host/bin/python -m pip download --require-hashes --only-binary=:all: --dest /tmp/faultlens-platform-wheels -r requirements-tui.txt
docker pull python@sha256:726d304906fa5eb468e5531e366548d1903286352f5adb54ef508ac01fbd80c6
/tmp/faultlens-platform-host/bin/python scripts/platform_acceptance.py --target debian-12 --container
```

The Docker check fails instead of pulling an unprepared image automatically. It uses
a unique container-ID file and removes only that created container on failure/timeout.
The full suite retains existing CLI/Textual resource budgets. On an actual Ubuntu
24.04/Python 3.12 development runner with the reviewed frontend environment, also run:

```sh
.venv/bin/python scripts/platform_acceptance.py --target ubuntu-24.04 --frontend
```

Wrong OS/Python/architecture/frontend setups fail before native collection. This is
a developer qualification tool; operator-server checks remain
[the existing read-only server checker](../server-check.md), without Docker or any
new daemon. No failure of an optional diagnostic source is labeled a healthy server.

## Evidence and open gates

| Environment | Automated scope | Remaining acceptance |
| --- | --- | --- |
| Debian 12, Python 3.11.18, pinned x86-64 container | Native CLI before/after reviewed frontend, full suite; missing systemctl/journalctl/ss/Atop are handled explicitly | Booted service manager, real incident history, SSH and workload impact |
| Ubuntu 24.04, Python 3.12, hosted x86-64 CI | Full suite and native CLI with reviewed frontend; each exact revision is gated by the baseline check | Operator configuration, existing administrator access, SSH and workload impact |
| Development Python 3.14.4 | Full synthetic regression suite | Does not select a supported server distribution |
| Operator server and materially different second server | Existing read-only server checker/manual workflow available | OS/tool/access observations, incident usefulness and terminal acceptance not yet recorded as approved |

Use the baseline result for the exact commit as execution evidence. Do not substitute
a previous green run or the table itself for an actual check. Candidate/implementation,
automated verification and operator acceptance remain separate statuses.

Local verification on 2026-11-16: all 541 tests passed on development Python 3.14.4
and in pinned Debian/Python 3.11.18. Both Debian native passes (frontend absent and
reviewed) completed all five contracts. Network coverage was partial and system
journal evidence unavailable, as expected for this minimal image; these states were
reported without a healthy-server or no-fault claim. Ubuntu execution is enforced by
the same baseline check for the exact PR/merge revision.

Failed container runs expose only bounded test identities/counts and the process
state/exit code. Assertion bodies, subtest payloads and native evidence are excluded
from this failure summary. Native contract failures point to the fixed local
reproduction command; the same container cleanup and qualification gates apply.
