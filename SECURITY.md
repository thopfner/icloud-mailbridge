# Security policy

## Reporting a vulnerability

Use this repository's **Security → Report a vulnerability** private reporting
form: https://github.com/thopfner/icloud-mailbridge/security/advisories/new

Do not post credentials, email contents, tokens, authenticator secrets or
deployment details in public issues. Provide a minimal synthetic reproduction,
affected revision, impact and suggested mitigation. No response-time guarantee
is offered.

## Scope and trust boundaries

This is a self-hosted, single-owner project. It has not received an independent
security audit and provides no guarantee against compromise.

- The host administrator and running service can access decrypted credentials.
- The ChatGPT account and OAuth scopes authorize mailbox access and mutations.
- Email, attachment content, sender headers and model output are untrusted.
- Review tokens bind action content, revision and connection, not human intent.
- Private administration supplements password/TOTP; it does not replace them.
- Only one process/worker is supported. Do not scale horizontally without
  redesigning security and action serialization.

Use an Apple app-specific password, protect your VPS/registrar/client accounts,
keep the OS and dependencies patched, and restrict SSH and owner pages to a
private network. See SECURITY_OPERATIONS.md for response and recovery.

Only the current main branch is maintained on a best-effort basis. Review and
test updates before deployment. Synthetic fixture passwords in tests are not
deployment credentials and must never be reused.
