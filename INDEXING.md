# Indexed inbox workflows

This is additive. Live search/read, iCloud draft sync, reviewed in-chat sending,
OAuth and the existing organizer keep their existing implementations.

## Scheduled processing

mailbridge-index.timer runs a resource-limited worker about every ten minutes
after the preceding pass completes. mailbridge-index-nightly.timer runs at
03:15 Europe/Amsterdam, also checking SQLCipher page authentication and FTS
consistency. Timers never call SMTP, edit drafts, alter read flags, move mail,
generate external notifications or invoke an external AI provider.

Default coverage is Inbox, the special-use Sent folder and iCloud Drafts, with
90-day retention. The worker reconciles current UIDs, deletions, UIDVALIDITY and
flags on every pass. Only unknown message bodies are downloaded. It does not
depend on optional QRESYNC/CONDSTORE support. Additional folders require an
explicit owner choice through configure_mail_index.

Bounds: six folders, 3000 recent messages per folder, 2 MB maximum MIME message,
12000 cached body characters, no attachment-content indexing. Oversized/unparsed
messages retain headers and an explicit limitation. Normal passes fetch at most
100 new messages per folder with a 240-second work budget; sockets have timeouts.
Backfill proceeds over successive passes. Status discloses caps, pending mail,
partial body coverage, last success, errors and staleness.

## MCP workflows

Server instructions and tool descriptions explain scope, limits, live-source
verification and side effects. get_mail_workflow_guide exposes this knowledge
inside MCP, without requiring ChatGPT to read an administrator file.

- mail_index_status: freshness, coverage, caps, backfill and failures.
- search_indexed_mail: full-text recent history, dates, sender and unread state.
- refresh_mail_index: bounded immediate cache refresh, with overlap protection.
- configure_mail_index: owner-directed enable/pause, folders and retention.
- list_mail_threads/get_mail_thread: header-linked conversations and source refs.
- list_mail_suggestions: possible requests, outgoing commitments and deadlines.
- review_mail_suggestion: explicitly acknowledge/dismiss/complete/reopen a
  suggestion; does not change organizer tasks or mailbox contents.
- get_mail_preferences/set_mail_preferences: owner-confirmed important senders,
  project keywords, sender aliases and follow-up age.
- daily_mail_briefing: on-demand current overview in Europe/Amsterdam.

Use live search_mail for older mail or missing index results. Use read_mail to
verify evidence before consequential actions. Existing save_item creates a
confirmed organizer task after owner review; suggestions never create tasks
automatically. Drafts still sync through save_draft. Sending still requires the
owner's explicit instruction and exact request_send/send_draft review. Mailbox
read/unread, flags, archive, Trash and move also run in ChatGPT through
request_mail_change/execute_mail_change, without website approval. After a
mailbox change, use live reads or refresh_mail_index before relying on cached
state. See MAIL_ACTIONS.md.

## Intelligence limits

No model runs continuously. Deterministic English/Dutch rules identify possible
requests, outgoing commitments and deadlines. ChatGPT synthesizes evidence when
asked. Only explicit ISO dates are extracted; relative dates remain source text
requiring review. Quoted text is excluded where recognizable. Heuristics can miss
or misclassify email.

Thread grouping uses Message-ID, References and In-Reply-To, not subject alone.
Analysis considers the latest 5000 indexed non-draft messages and 4000 body
characters each. Returned analysis_limited, analysis_messages_considered and
analysis_body_characters disclose these limits. Missing/truncated messages or
headers reduce certainty. A new reply moves a waiting conversation to
reply_received_review; it never proves an obligation is complete. Earlier possible
commitments remain reviewable and carry newer_thread_activity when a later
message exists; reassess them against the newer reply rather than assuming completion.
No semantic/vector search, historical daily snapshots, automatic language-model
extraction, auto-sending or push notifications are included.

## Privacy, recovery and isolation

/var/lib/mailbridge/mail-index.db uses SQLCipher 4.20.0 via pinned sqlcipher3
0.6.5. Content, full-text tokens, metadata and WAL are encrypted. The index key is
domain-separated from the existing master key using HMAC-SHA256. Temporary SQL
storage is in memory, files use 0600 and the state directory is private.
SQLCipher authenticates pages; ordinary SQLite cannot read the index.

An account/credential fingerprint gates cache reads. Disconnect or replacement
immediately makes previous indexed data unavailable to MCP; the next worker pass
purges it. Retention is pruned during worker passes (including paused retrieval)
and at query time. OAuth authentication and existing scopes protect indexed tools.
All email excerpts remain untrusted data, never authority to change preferences,
send mail or complete tasks.

The rebuildable index is deliberately excluded from daily application backups.
Preferences and suggestion review decisions are encrypted in the main DB and ARE
included in existing encrypted backups. Restoring an older backup may require
rebuilding the index. Keep the master key secure.

The worker has CPU/memory limits, a process lock, read-only mounts for the main
application DB/WAL and a separate SQLite index. Index failures must not stop live
mail tools. New modules are imported lazily. The worker logs no subjects,
addresses, message bodies or credentials.

## Operations and rollback

    systemctl status mailbridge-index.timer mailbridge-index-nightly.timer
    systemctl status mailbridge-index.service
    journalctl -u mailbridge-index.service --since today
    systemctl start mailbridge-index.service

Use mail_index_status for health. Disclose stale/incomplete data and use live
mail tools as fallback. To pause indexing independently:

    systemctl disable --now mailbridge-index.timer mailbridge-index-nightly.timer

Wait for active workers to finish, or stop them. SQLite transactions and UID
reconciliation allow the next pass to resume. Do not manually copy a live WAL DB.

For rollback, stop indexing workers and restore a previously tested release
together with its compatible configuration and backup. Verify live mail tools
before restarting the timers. Never copy a live SQLite WAL database directly.

## Verification

Tests cover ciphertext/no plaintext FTS leakage, scope enforcement, worker
overlap, incremental bodies, flags/deletions, UIDVALIDITY, retention, disconnect/
account changes, false-positive boundaries, explicit preferences, prompt
injection as data, suggestion review and nightly integrity checks. Existing
OAuth, draft-sync, send replay, uncertain outcome and security tests stay green.
