# Pre-publication security checklist

Publication is a separate, explicit owner decision. Keep this repository private.
No license is selected by this baseline. Do not merge or publish automatically.

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

- [ ] General / Danger Zone: preserve **Private** visibility. Consider disabling
  private-repository forking where the account/plan permits it.
- [ ] General: add a truthful pre-release description; keep website empty until an
  approved destination exists. Keep unused Pages, wiki and discussions disabled.
- [ ] Actions / General / Actions permissions: select **Allow select actions and
  reusable workflows**; allow GitHub-owned actions only for this baseline. If a
  specific allowlist is supported, restrict it to `actions/checkout`.
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
  dismiss stale approvals, require `Security baseline / baseline`, block force pushes
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
No dependency installs, caches, report uploads, or privileged checks are required.
A malicious contributor able to modify the checks or bypass CI can defeat them.
CODEOWNERS and passing CI do not enforce review without GitHub branch protection.
