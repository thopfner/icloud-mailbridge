# Multi-provider platform direction — recorded 2026-11-16

Requested by the owner after reviewing the iCloud implementation. This records
the agreed direction for future planning; it does not authorize or claim that
additional providers have already been implemented.

## Current state

Mailbridge is an iCloud-specific implementation on a reusable foundation.
Apple IMAP/SMTP endpoints are fixed, one mailbox credential setting is used,
and the index assumes one active account. It is not yet a multi-account or
multi-tenant platform.

Reusable components include the ChatGPT MCP integration, encrypted storage,
search/briefings, draft and send reviews, explicit user send authorization,
revision checks, duplicate-send protections, and private administration.

## Recommended architecture

Keep one consistent user-facing set of MCP actions and introduce provider
adapters plus proper account management:

| Provider | Connection |
| --- | --- |
| iCloud | Existing TLS IMAP/SMTP and Apple app-specific password |
| Gmail / Google Workspace | Gmail API with OAuth |
| Outlook / Microsoft 365 | Microsoft Graph with OAuth |
| Other tested providers | IMAP/SMTP with explicit capability checks |

Use provider-native threading and reply/draft facilities where appropriate;
Gmail thread IDs and Microsoft Graph reply drafts must be handled by their
adapters. A generic SMTP credential swap alone is insufficient.

## Required invariants

- Unified search, briefings and follow-ups across selected accounts, with
  every result labelled by its originating account.
- Account-bound identifiers, drafts, operations, idempotency keys and send
  reviews. Replies default to the receiving account; new mail selects an
  explicit sender/account. No accidental cross-account actions.
- Drafts sync to the originating mailbox and remain visible in mail clients
  connected to that account.
- Consistent reply threading and quoted history, review, explicit sending,
  stale-draft rejection and duplicate/uncertain-send safeguards.
- Honest unsupported-capability errors; never silently substitute a different
  operation. Respect differences in labels/folders, moves, drafts and sync.
- Separate encrypted credentials, per-account authorization/revocation, cache
  isolation and independent disconnection before provider expansion.
- Consolidation increases exposure if the server is compromised; storage
  separation alone does not protect credentials from a root compromise.

## Delivery sequence

1. Extract iCloud into a provider adapter and introduce account isolation,
   preserving existing iCloud behavior through contract/regression tests.
2. Add one additional provider (for example Gmail), then run the same
   behavioral contract tests against both.
3. Expand providers and unified workflows after account/sync/action correctness
   is verified. Multi-user SaaS tenancy is a separate scope.

Reference documentation:
- https://developers.google.com/workspace/gmail/api/guides/threads
- https://learn.microsoft.com/en-us/graph/api/message-createreply
- https://support.apple.com/102525
