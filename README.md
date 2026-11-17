# iCloud Mailbridge

A self-hosted, single-owner MCP server for managing Apple iCloud Mail through
ChatGPT. Read and search email, draft threaded replies with quoted history,
sync drafts to Apple Mail, and send explicitly requested messages through one
OAuth connection.

Mailbridge uses **IMAP over TLS for reading and draft synchronization** and
**SMTP with mandatory STARTTLS for sending**, authenticated with an Apple
app-specific password. It never needs your main Apple Account password.
This is an independent project, not affiliated with Apple, OpenAI or Mailopoly.

## Features

- Live mail search, safe text reading and supported text attachments.
- Drafts saved to iCloud Drafts and visible in Apple Mail.
- Replies preserve Message-ID references, reply recipients and quoted history.
- Revision-bound send previews, duplicate prevention and explicit uncertain
  outcomes after ambiguous network failures.
- Read/unread, flags, archive, Trash and moves with exact-message reviews.
- Encrypted recent-mail index, full-text search, thread views and follow-ups.
- On-demand briefings and evidence-linked organizer tasks, bills and events.
- OAuth authorization-code flow with PKCE, scoped tools and rotating tokens.
- Private-network owner administration, password plus TOTP authentication.

Mailbox actions work in the connected chat without per-action website login.
Initial connection and credential/security administration remain protected.
No background model calls, autonomous sending or OpenAI API key are required.

## Getting started

This is an administrator-operated Linux service, not a hosted sign-up service.
Read [DEPLOYMENT.md](DEPLOYMENT.md) before connecting a real mailbox. You need
a VPS, a domain with valid HTTPS, private administration access and an Apple
app-specific password. Keep credentials out of chats, issues and Git.

1. Install the pinned dependencies and SQLCipher on your server.
2. Configure your own hostname, encryption key and trusted administration CIDRs.
3. Install the supplied systemd units and Caddy configuration.
4. Privately run `bin/mailbridge setup-owner` and `bin/mailbridge setup-mail`.
5. Add `https://YOUR_HOST/mcp` to a compatible ChatGPT account using OAuth.
   Complete sign-in and consent from the allowed administration network.

Custom MCP availability and host-side tool confirmations depend on the client
account/workspace. The server currently restricts OAuth callbacks to supported
ChatGPT URLs; it is not a general OAuth provider for arbitrary clients.

Example requests:

- "Summarize my unread email and show the messages needing a reply."
- "Draft a reply to this message; show the recipients and complete draft."
- "Send the draft I just reviewed."
- "Show outstanding follow-ups and the source emails."
- "Move this message to Trash."

## Safety and limitations

The current implementation supports **one iCloud mailbox and one owner**.
[PLATFORM_EXPANSION.md](PLATFORM_EXPANSION.md) records a future multi-provider
architecture; Gmail, Microsoft 365 and multi-user tenancy are not implemented.

Email content is untrusted. Review recipients, quoted content and consequential
actions. Review tokens bind exact content to a connection; they are not
independent proof of human consent. A compromised client with send/write scopes
can misuse those permissions. Keep host-side confirmations enabled.

Encryption at rest does not protect credentials from root or running-service
compromise. Run only one application worker: security and action serialization
use process locks. See [SECURITY.md](SECURITY.md) and
[SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md).

Drafts are plain text. Quotes include earlier history already present in the
selected parent, not missing messages reconstructed from elsewhere. Apple Mail
edits are detected as conflicts rather than continuously merged. SMTP acceptance
does not guarantee recipient delivery; ambiguous sends are never retried
automatically.

Limits include 10 recipients per draft, 20 SMTP submissions per day, 2 MB
message reads and 100 KB supported text attachments. Indexing is bounded and
may be incomplete; check freshness and use live reads before consequential work.
There is no permanent-deletion tool or bulk sending.

## Documentation

- [Deployment](DEPLOYMENT.md)
- [Threaded and quoted replies](REPLIES.md)
- [Mailbox changes](MAIL_ACTIONS.md)
- [Indexing and inbox intelligence](INDEXING.md)
- [Security operations](SECURITY_OPERATIONS.md)
- [Testing and release validation](VALIDATION.md)
- [Contributing](CONTRIBUTING.md)
- [Multi-provider roadmap](PLATFORM_EXPANSION.md)

## Development

The release was tested on Python 3.14 with SQLCipher available.
Use a disposable environment on your development server:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/python -m pytest -q
.venv/bin/pip check
```

Tests create temporary configuration, random encryption keys and synthetic mail
transports. They do not use production mailbox credentials or send real email.
SQLCipher headers/libraries and a C compiler may be needed to build sqlcipher3.
See [DEPLOYMENT.md](DEPLOYMENT.md) for system prerequisites.

## License

[MIT](LICENSE). Third-party dependencies retain their respective licenses.
