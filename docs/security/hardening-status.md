# Repository hardening status

Live repository controls were rechecked on 2026-11-15 during the corrected frontend
stabilization. This is a dated audit, not continuous monitoring. The owner previously
authorized public pre-release visibility and merging reviewed staging PRs after all
required checks pass. The owner has now approved GPL-3.0-or-later; [LICENSE](../../LICENSE)
and [NOTICE](../../NOTICE) establish that grant (approved 2026-11-16). No application release is authorized.

## Verified controls

- Default branch main; only main and staging are used by this task.
- Main requires baseline, analyze and CodeQL. Protection applies to administrators;
  force pushes and deletion are blocked. Staging also blocks force pushes/deletion
  while permitting the authorized two-branch development/synchronization workflow.
- Actions are restricted to actions/checkout and github/codeql-action init/analyze
  patterns. Full commit SHA pinning is administratively required. The default token
  is read-only and workflows cannot approve pull requests.
- Secret scanning and push protection are enabled. Private vulnerability reporting
  is enabled. Dependabot automatic security-update PRs remain disabled; version PRs
  remain paused to preserve the main/staging-only policy.
- The corrected frontend CI retains the same actions and token scope. Its only new
  install step creates a temporary venv and installs the exact wheel-hashed frontend
  lock using --require-hashes and --only-binary=:all:. The policy mutation tests reject
  dropping either constraint or substituting commands, actions, triggers or permissions.

The optional Textual closure was audited separately; see [dependency review](../third-party.md).
No runtime reports or source evidence are uploaded by Faultlens. CodeQL remains a CI
service with its existing job-scoped security-events write permission.

## Audit boundaries and release gates

The earlier 2026-11-11 audit described the initial 11-byte repository and first
hardening PR. Those historical counts and future-tense implementation statements
are superseded; they are not current release-readiness evidence. Current application
verification is recorded in the corrected frontend/stabilization review.

Gitleaks working-tree/history scans and the standard-library baseline complement
GitHub controls, not a guarantee that every secret or unsafe change is detectable.
The runner image, system Python, package registry and CodeQL tool bundle remain CI
supply-chain dependencies; wheel/action hashes constrain content without proving
absence of unknown flaws.

Solo maintenance has no independent review requirement. Account 2FA/recovery and
any additional maintainer remain owner decisions, not controls changed by this task.
Existing public copies cannot be recalled. The project license is GPL-3.0-or-later.
Support policy, actual server acceptance, third-party distribution notices and exact
publication artifacts remain open release gates.
No new administrative GitHub setting is required for the corrected frontend.

Live views: [branch protection](https://github.com/mfuryto/faultlens/settings/branches),
[Actions](https://github.com/mfuryto/faultlens/settings/actions),
[security](https://github.com/mfuryto/faultlens/settings/security_analysis).
