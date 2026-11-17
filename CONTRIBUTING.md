# Contributing

Use synthetic data and a disposable development server. Never connect tests
to a real mailbox or commit credentials, dumps, private logs or production
configuration. Report vulnerabilities privately through SECURITY.md.

Open an issue describing the problem or proposed capability before a substantial
change. Keep pull requests focused; explain behavior, compatibility, tests and
security implications. Run the complete pytest suite and pip check.

Preserve these invariants:

- Read tools and indexing never send or mutate mail.
- Consequential actions require scoped access and explicit user direction.
- Reviews bind exact recipients/content/revision and connected account.
- Ambiguous remote mutations are not automatically retried.
- No blanket EXPUNGE, attachment execution or remote asset fetching.
- Owner administration remains private and authenticated.
- No secrets or mail content in logs.
- Single-worker operation until synchronization is deliberately redesigned.

Changes to reply composition must cover nested quotes, HTML-only mail,
attachment exclusion, edits, draft/SMTP serialization and source threading.
Provider expansion must begin with account isolation and contract tests.

Public release history starts from a sanitized source snapshot. Private
deployment history and runtime data are intentionally not included.
