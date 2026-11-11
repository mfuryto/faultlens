# Repository hardening status

Verified administrative configuration on 2026-11-11. Recheck live GitHub settings
before relying on this snapshot. The owner authorized public visibility after the
content and history audit. The owner subsequently authorized the agent to merge
once security checks pass. No release or license selection was authorized.

## Enabled controls

- Public pre-release repository; only `main` and `staging` branches.
- Main requires an up-to-date PR, resolved conversations, linear history,
  GitHub Actions checks `baseline` and `analyze`, and the CodeQL findings check
  `CodeQL`. Independent and code-owner approvals are not required for this solo
  project. The agent may merge when authorized and all checks pass. Administrators are subject
  to protection. Force pushes and deletion are blocked.
- Staging permits direct development pushes, requires linear history, and blocks
  force pushes and deletion, including for administrators. This supports a two-branch
  development model without creating disposable feature branches.
- Actions allow only `actions/checkout@*`, `github/codeql-action/init@*`, and
  `github/codeql-action/analyze@*`; full commit SHA pinning is required administratively.
- Default workflow token is read-only and cannot approve pull requests.
- Logs and artifacts expire after seven days. Auto-merge and automatic deletion of
  merged branches are disabled, preserving staging.
- Dependency graph and Dependabot vulnerability alerts are enabled. Automated
  security-update PRs were already disabled and were not changed. Version PRs are
  paused in the proposed Dependabot configuration to preserve the two-branch model.
- Secret scanning, push protection, and GitHub private vulnerability reporting are
  enabled. Use the Security tab's private reporting route; never disclose publicly.
- The PR adds CodeQL Python security-extended analysis on main/staging pushes and
  main PRs, plus a weekly schedule once the workflow reaches the default branch.
  The pinned init/analyze actions have job-scoped `security-events: write` only;
  the baseline retains read-only permission. No default-setup workflow is enabled.

## Validation

The initial repository had a single commit with an 11-byte README. The expanded
audit found no releases, tags, existing artifacts, deploy keys, webhooks, Actions
secrets, variables, environments, issue comments, PR comments, or commit comments.
The only issue/PR was the hardening PR. Author addresses used GitHub noreply metadata.

Gitleaks v8.30.1 was obtained from the official release and its archive SHA-256 was
checked against the published release checksum. Local `gitleaks git --log-opts=--all`
and `gitleaks dir` scans with redacted output found no leaks. This is evidence from
selected detectors, not proof that no sensitive information could ever exist.
The dependency-free policy checks and all eleven tests passed. A CodeQL finding
about sensitive logging was addressed by logging fixed categories only, never
scanner-derived text or paths. Check live PR statuses
for the final GitHub-hosted baseline and CodeQL results; local checks do not substitute
for CodeQL execution.

## Remaining gates

- The hardening PR can merge only after all required checks pass. SECURITY,
  CODEOWNERS, Dependabot configuration and scheduled workflows become active on
  the default branch after merge. Check the live PR for merge state.
- There is only one administrator/collaborator. The owner accepted a solo-maintainer
  policy without independent review. CODEOWNERS documents ownership but does not
  impose an approval requirement. Independent review remains a useful future option.
- No license is granted, and no diagnostic application or runtime security controls
  exist yet. Public visibility is not a supported application release.
- The runner image, installed Python, and CodeQL tool bundle are CI supply-chain
  dependencies. Action commit SHAs are pinned; the downloaded tool bundle and runner
  image are not a fully reproducible toolchain. No such tooling is a runtime dependency.
- Public copies and forks cannot be recalled by later making the repository private.
- Account 2FA, recovery codes and a second trusted maintainer require owner decisions;
  no personal account settings or collaborators were changed.

Live views: [branch settings](https://github.com/mfuryto/faultlens/settings/branches),
[Actions settings](https://github.com/mfuryto/faultlens/settings/actions),
[security settings](https://github.com/mfuryto/faultlens/settings/security_analysis),
and [hardening PR](https://github.com/mfuryto/faultlens/pull/1).
