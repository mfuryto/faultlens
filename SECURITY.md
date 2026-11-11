# Security policy

## Status and scope

Faultlens is pre-release and has no supported application versions. Security
requirements in this repository describe intended behavior, not a claim of a
completed or audited implementation.

## Report privately

Do not disclose vulnerabilities, credentials, host identifiers, or diagnostic evidence
in public issues, pull requests, CI logs, or discussions.

If GitHub private vulnerability reporting is enabled, use the repository Security
page's **Report a vulnerability** entry:
https://github.com/mfuryto/faultlens/security/advisories/new

This facility is not currently verified as available for this private repository.
If unavailable, contact maintainer `@mfuryto` through an existing private channel
and request a secure reporting channel before sending details. Do not open a public
issue to establish contact. There is currently no published security email address
or guaranteed response time; establishing a verified private contact is a release blocker.

Include affected revision, minimal synthetic reproduction, impact, and remediation
ideas. Share only sanitized evidence; arrange encrypted transfer separately if raw
material is essential. Never send live secrets. Coordinate disclosure privately.

If a secret enters Git, revoke or rotate it first, assess access and CI artifacts,
then coordinate history cleanup. Deleting the latest file does not remove history.
