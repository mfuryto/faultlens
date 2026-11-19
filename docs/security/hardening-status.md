# Repository hardening status

Live repository controls were rechecked on 2026-11-19 during version 1.0
preparation. This is a dated audit, not continuous monitoring. The owner previously
authorized public pre-release visibility and merging reviewed staging PRs after all
required checks pass. The owner has now approved GPL-3.0-or-later; [LICENSE](../../LICENSE)
and [NOTICE](../../NOTICE) establish that grant (approved 2026-11-16). The owner explicitly authorized completion and publication of version 1.0 on 2026-11-19.

## Verified controls

- Default branch main; only main and staging are used by this task.
- Main requires baseline, analyze, CodeQL and both Debian/Ubuntu package checks. Protection applies to administrators;
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
The latest-version security policy, owner-server SSH feedback, dependency audit,
third-party notices and release qualification are documented in
[release readiness](../release-readiness.md). Another Ubuntu-server package test is
planned by the owner after delivery, not a release blocker.

Administrative counts rechecked for this release: one collaborator; no deploy keys,
webhooks, environments or Actions secrets. This does not inspect the owner's account
2FA or recovery state. Dependabot alerts and private vulnerability reporting are
enabled; automated update PRs remain paused under the two-branch policy.

Live views: [branch protection](https://github.com/mfuryto/faultlens/settings/branches),
[Actions](https://github.com/mfuryto/faultlens/settings/actions),
[security](https://github.com/mfuryto/faultlens/settings/security_analysis).
