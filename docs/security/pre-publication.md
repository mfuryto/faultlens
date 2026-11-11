# Pre-publication security checklist

The owner explicitly authorized public visibility after a clean-content audit on
2026-11-11. The repository is now public for pre-release review; no application
release is published. No license is selected. Do not merge or release automatically.
The historical private-plan limitations below describe the initial audit, not the
current configuration. See [hardening status](hardening-status.md) for current settings.

## Repository and history

- [ ] Review all branches, tags, commit messages, author email metadata, reachable
  blobs, releases, attachments, issues, PRs, wikis, Pages, packages and Actions artifacts.
- [ ] Run the baseline checks with all refs fetched; supplement with a maintained
  secret scanner and manual review. Revoke exposed credentials before history repair.
  Local scans cannot inspect deleted remote refs, GitHub caches, or existing clones.
- [ ] Confirm no real host logs, captures, reports, personal data, internal addresses,
  credentials, local environments, binaries or unsafe fixtures are committed.
- [ ] Approve a license explicitly and review third-party notices before release.
- [ ] Verify actual implementation against the threat model; document remaining gaps.

## Manual GitHub settings

Paths refer to repository Settings. Availability depends on the private-repository plan.

- [ ] General / Danger Zone: verify visibility matches the owner's explicit decision.
  Public visibility permits copying and forking; later visibility changes cannot recall copies.
- [ ] General: add a truthful pre-release description; keep website empty until an
  approved destination exists. Keep unused Pages, wiki and discussions disabled.
- [ ] Actions / General / Actions permissions: select **Allow select actions and
  reusable workflows**; allow GitHub-owned actions only for this baseline. If a
  specific allowlist is supported, restrict it to `actions/checkout@*` and
  `github/codeql-action/init@*` / `github/codeql-action/analyze@*`, with SHA pinning required.
- [ ] Actions / General: enable **Require actions to be pinned to a full-length
  commit SHA** if offered. The local policy remains necessary if unavailable.
- [ ] Actions / General / Workflow permissions: retain **Read repository contents
  and packages permissions** and leave **Allow GitHub Actions to create and approve
  pull requests** unchecked. Set shortest practical log retention (for example 7 days).
- [ ] Security / Advanced Security (or Code security and analysis): enable dependency
  graph and Dependabot alerts. Keep automatic security-update PRs disabled while
  the main/staging-only branch policy applies; review alerts and update on staging. Dependabot version updates also need the default-branch config;
  the pip entry has nothing to update until a manifest is added. Version PR creation
  is paused (`open-pull-requests-limit: 0`) because Dependabot creates extra branches.
  Both ecosystem entries target staging if bot branches are approved later.
- [ ] Security: enable secret scanning and push protection if available. If unavailable
  for this private repository, record the gap and use local scanning plus review.
- [ ] Security: enable private vulnerability reporting if offered and test the private
  reporting route. Otherwise publish a verified private security contact before release.
- [ ] Security: evaluate code scanning availability and supported language setup once
  application code exists. Do not imply the baseline workflow provides CodeQL coverage.
- [ ] Rules / Rulesets or Branches: current plan returns an upgrade requirement for
  private repositories. Do not make the repository public to unlock this. If the owner
  chooses an eligible plan, protect **main and staging**, require PRs and owner review,
  dismiss stale approvals, require `baseline` and `analyze`, block force pushes
  and deletions, and restrict bypasses. Verify the exact check name after a CI run.
- [ ] Collaborators: audit least privilege, owner 2FA/passkeys and recovery access.
  Only one administrator currently exists; independent review and recovery remain gaps.
- [ ] Keep Actions secrets, environments, deployment keys and webhooks empty unless
  separately justified and reviewed. Confirm no automation merges PRs or publishes.

## Audit snapshot — 2026-11-11

The fetched repository contained one commit, one 11-byte README, `main` only, no tags,
no application, manifests, workflows or license. Author metadata used GitHub noreply
addresses. Local reachable-history inspection found no credential material. No
webhooks, Actions secrets, Actions variables or environments were configured.
Description and homepage were empty; Pages, wiki and discussions were disabled.
Private forking was allowed. Actions allowed all actions, SHA pinning was not required,
and the workflow token was read-only with PR approvals disabled. Main was unprotected;
rulesets returned HTTP 403 with a private-plan upgrade requirement. Vulnerability
alerts were disabled and code scanning was not enabled. Secret scanning was disabled
according to the preceding audit; the current metadata response did not expose its
state, so recheck manually. This snapshot is not continuous monitoring.

## Limits of automated enforcement

The standard-library scanner detects selected credential formats and assignments,
suspicious file paths, binary/oversized tracked content, and unsafe synthetic fixture
patterns. It is not a comprehensive secret scanner or sanitization proof. Workflow
files intentionally use a constrained JSON subset of YAML; non-JSON workflows fail
closed. The runner image and system Python are GitHub-maintained mutable dependencies.
The baseline requires no dependency installs, caches, or diagnostic report uploads.
The separate CodeQL job downloads its analysis tools and uploads code-scanning findings
using only job-scoped security-events write permission.
A malicious contributor able to modify the checks or bypass CI can defeat them.
CODEOWNERS and passing CI require administrative protection to enforce review;
verify live branch protection rather than relying on this historical checklist.
