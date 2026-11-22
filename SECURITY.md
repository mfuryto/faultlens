# Security policy

## Status and scope

Security fixes target the latest published Faultlens version. The current release is 1.1.0.
Update to the latest patch before reporting a defect; older development previews are
unsupported. Support is best-effort without a guaranteed response time. No independent
security audit or comprehensive host-security assessment is claimed.

Faultlens is a read-only local fault-investigation tool. Existing account permissions
control source access; missing evidence and unknown causes must remain explicit.
Private bundled frontend dependencies are updated through a new Faultlens package.

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
