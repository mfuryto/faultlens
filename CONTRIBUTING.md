# Contributing

This public, pre-release repository uses English for code, documentation, comments,
commits, branches, workflows, and pull requests. No license is granted yet.

## Branch and review policy

Use only `staging` and `main`. Develop on `staging` and open a pull request to `main`.
Dependabot version PRs are paused to avoid creating extra branches; review alerts
and apply dependency updates manually on staging. Main requires a pull request and
owner review, passing security checks, and resolved conversations. Staging accepts
direct development pushes; force pushes and branch deletion are blocked on both
branches. A sole author cannot provide independent review of their own change.
Do not bypass main's review requirements to merge your own PR.

Run the README checks before pushing. Review the entire diff and new dependency
or workflow provenance. Never commit real diagnostic data, secrets, local settings,
private hostnames, addresses, or unsanitized reports. `.gitignore` is only a convenience;
it cannot prevent forced additions or remove previously tracked data.

## Secure implementation requirements

- Separate collection, normalization, diagnostic rules, rendering, and optional changes.
- Default to read-only, unprivileged operation. Handle denied access as unavailable
  evidence, not an invitation to run the whole application as root.
- Require a preview and explicit confirmation of exact configuration changes;
  fail closed in noninteractive operation. Document backup, rollback, and audit behavior.
- Invoke trusted absolute executable paths with validated argv, `shell=False`, a
  controlled environment, timeouts, bounded output, and no implicit sudo or pagers.
- Treat command output, journal text, files, and terminal escape sequences as hostile.
  Bound parsing, neutralize terminal controls, and test malformed and truncated input.
- Keep raw evidence local. Use private directories (0700), files (0600), restrictive
  umask, safe creation without following symlinks, explicit retention, and user-selected
  exports. Redaction is not proof of anonymity. No automatic upload or artifact export.
- Findings must retain source, time/boot identity, observation, reasoning, threshold,
  confidence, and limitations. A confirmed event is not necessarily a confirmed cause.
- Use synthetic fixtures and deterministic tests; never collect from the CI host.
  Sanitized recordings need a documented review and policy change before inclusion.
- Justify and inventory runtime dependencies and integrations, including licenses,
  provenance, supported versions, vulnerability review, and reproducibility strategy.
  Add a lock with hashes before installing Python dependencies in CI or releases.
- Document technical justification before adding a daemon, database, external service,
  or heavyweight dependency. Runtime network access and telemetry are out of scope.

## CI changes

Workflows use JSON syntax (valid YAML) so a dependency-free parser can enforce a
narrow policy. Keep actions pinned to full verified commit SHAs. Only standard GitHub
hosted runners and explicit read-only tokens are allowed. Never use privileged PR
triggers, self-hosted runners, secrets, dynamic shell expressions, cache restoration,
artifact uploads, dependency installation, or deployment in the baseline workflow.
The separate pinned CodeQL workflow has only job-scoped `security-events: write`
to upload source-code analysis findings to GitHub; it does not collect diagnostic
reports. CodeQL tooling is a justified CI-only dependency, never a runtime dependency.
A broader workflow requires a reviewed policy change and negative tests.

The baseline scanner is heuristic, not a complete secret detector or malware audit.
Review scanner changes carefully: code in a PR can weaken its own checks, if administrative protections are bypassed. See the security checklist for administrative controls.
