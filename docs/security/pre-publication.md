# Pre-publication security checklist

The repository is public for pre-release review under the owner's earlier explicit
authorization. This is separate from publishing an application release. No license
is selected. Reviewed staging PRs may merge only after all required checks pass;
release/tag/package publication still needs explicit owner approval.

## Release audit

- [ ] Recheck live controls against [hardening status](hardening-status.md); do not
  rely on initial/private-plan snapshots or future-tense instructions from old audits.
- [ ] Review branches/tags, author metadata, reachable history, releases, packages,
  artifacts, issues/PR attachments and other public surfaces for sensitive material.
- [ ] Run repository/history secret checks with all authorized refs fetched; revoke
  exposed credentials before any history repair. Existing clones/caches/deleted refs
  are outside local scanner coverage.
- [ ] Confirm no real host logs, reports, captures, private identifiers, credentials,
  local environments, native recordings or unsafe fixtures are in the source manifest.
- [ ] Audit the exact dependency lock, source/byte/output bounds, native command
  validation, terminal safety and known diagnostic limitations against the threat model.
- [ ] Complete actual target-host/SSH acceptance and record detector scope/calibration
  limitations before support or accuracy claims.
- [ ] Owner explicitly approves license, required third-party notices, support/version
  policy and the exact release artifacts. Passing CI does not authorize publication.

## GitHub verification

- [ ] Visibility still matches the owner's decision; unused deployment surfaces stay
  disabled unless separately approved. Do not change visibility to obtain plan features.
- [ ] Main protection applies to administrators, requires baseline/analyze/CodeQL and
  blocks force pushes/deletion. Staging remains protected against force/deletion while
  allowing the authorized direct development and synchronization workflow.
- [ ] Actions retain the reviewed allowlist, complete SHA pins and least-privilege
  workflow tokens. Pull-request approvals by workflows remain disabled.
- [ ] Dependency alerts, secret scanning/push protection and private vulnerability
  reporting remain active. Test the private reporting route without posting real secrets.
- [ ] Update automation respects the two-branch policy. Review/re-hash dependency
  changes on staging; never disable a required check to make a PR merge.
- [ ] Review collaborator access, owner 2FA/passkeys and recovery arrangements. A
  solo-maintainer policy does not provide independent review or account recovery.
- [ ] Audit secrets, deploy keys, hooks, environments and artifact/log retention;
  additions require a concrete use and review. No automatic release workflow is implied.

## Enforcement limits

The source scanner checks selected credential patterns, sensitive paths, binary/large
content and synthetic-fixture constraints. It is not a sanitization proof. Workflow
files use a deliberately constrained JSON subset of YAML. The exact optional-frontend
install is allowed only with wheel hashes and binary-only resolution; all action SHA,
trigger and token restrictions remain enforced. CodeQL and advisory scans add coverage
without proving complete safety. A contributor able to replace checks or bypass
protection can defeat local enforcement; verify administrative controls separately.
