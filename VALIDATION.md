# Public release validation

The initial public release is exported from a working single-owner iCloud
deployment, with a fresh Git history. Private deployment logs, host addresses,
host-key fingerprints, recovery paths, credentials and runtime data are not
part of this repository.

The source deployment passed 162 regression tests, plus a live synthetic
iCloud draft check covering reply headers, dated quotation, nested history and
exact body preservation. SMTP was disabled for that live check; diagnostic
drafts were moved to Trash. No real emails were sent.

The public export removes deployment-specific SSH/domain rewrite commands.
Owner/mailbox setup, revocation, maintenance and status remain available.
Network setup is explicit in DEPLOYMENT.md and never silently rewrites firewall,
SSH or reverse-proxy access rules.

Publication checks are performed against the exported tree on the VPS:
full regression suite, dependency consistency, secret scanning and identifying
metadata checks. These are release checks, not an independent security audit
or a guarantee that the software is free of defects.

## Initial publication checks — 2026-11-17

- Public export regression suite: 162 passed, 43 dependency deprecation warnings.
- pip check: no broken requirements.
- pip-audit against requirements.lock: no known vulnerabilities reported.
- Gitleaks 8.26.0 directory scan: no leaks found.
- Explicit private-identifier scan and documentation-link checks passed.
- Reviewed address literals: only loopback and reserved documentation/test
  networks remain. No production deployment domain/IP, recovery path or host
  fingerprint is included.
- No production runtime code/configuration or mailbox content was changed for
  publication. No real emails were sent.
