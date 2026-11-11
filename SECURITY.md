# Security policy

## Status and scope

Faultlens is pre-release and has no supported application versions. Security
requirements in this repository describe intended behavior, not a claim of a
completed or audited implementation.

## Report privately

Do not disclose vulnerabilities, credentials, host identifiers, or diagnostic evidence
in public issues, pull requests, CI logs, or discussions.

Use the repository Security
page's **Report a vulnerability** entry:
https://github.com/mfuryto/faultlens/security/advisories/new

GitHub private vulnerability reporting is enabled. This is the established private
reporting route; no separate security email address or guaranteed response time is
published. If GitHub reporting is unavailable, use an existing private maintainer
channel to arrange secure contact. Do not post vulnerability details in public issues.

Include affected revision, minimal synthetic reproduction, impact, and remediation
ideas. Share only sanitized evidence; arrange encrypted transfer separately if raw
material is essential. Never send live secrets. Coordinate disclosure privately.

If a secret enters Git, revoke or rotate it first, assess access and CI artifacts,
then coordinate history cleanup. Deleting the latest file does not remove history.
