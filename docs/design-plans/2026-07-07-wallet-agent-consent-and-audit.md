# Wallet Agent Consent and Audit Design

## Summary

The auth.md claim ceremony is the human-in-the-loop gate for agent onboarding: an agent registers,
receives a `claim_token` + 6-digit `user_code`, and a human must confirm at the advertised
`verification_uri` before the identity flips `active → claimed` and the agent gets a usable
credential. Today that gate is advertised in the AS metadata (`oauth_server_metadata.rs`) but the
server endpoint is unimplemented (MM-170) and there is **no user-facing surface at all**: no way to
approve a claim, no way to see which agents are bound to your identity, no way to revoke one, and
no record of what an agent did.

This plan builds the Obsign side of the story — the product thesis ("see and control exactly what
touches your identity") extended to agents — plus the server pieces it needs: the claim-ceremony
endpoints (MM-170), an agent-management API for the wallet, and an immutable agent-action audit
log modeled on the existing `transfer_audit_events` pattern (V030).

## Definition of Done

### Server (crates/pds)

1. **Claim ceremony endpoints (MM-170).** `POST /agent/identity/claim` per the auth.md spec
   (already specced in the Linear issue): validates `claim_token`, creates/updates the
   `agent_claim_attempts` row, returns `registration_id`/`claim_attempt_id`/`status`/`expires_at`.
   A confirmation endpoint (wallet-authenticated, session or OAuth token of the bound account)
   accepts the `user_code`, flips the identity `active → claimed`, and completes the attempt.
   Expiry sweeps use the existing background-sweeper pattern (`account_reaper`/`blob_gc` style).

2. **Agent management API** for the bound account (wallet-authenticated; these are per-account,
   not operator/admin routes):
   - `GET /v1/agents` — list agent identities bound to the caller's DID: registration id, type,
     issuer/subject, scopes, status, created/claimed timestamps, last-used timestamp.
   - `POST /v1/agents/{registration_id}/revoke` — set `status = 'revoked'`; refuse for
     identities not bound to the caller.
   - `GET /v1/agents/{registration_id}/audit` — paginated audit events for that agent.

3. **Agent audit log.** New migration `VNNN__agent_audit_events.sql`: append-only table
   (`id`, `registration_id`, `did`, `event_type`, `detail` JSON, `created_at`), written from the
   points where agent activity is attributable via the `registration_id` token claim (see the
   [scope-enforcement plan](2026-07-07-agent-scope-enforcement.md), a prerequisite): registration,
   claim initiated/confirmed/expired, token exchanged, repo writes, blob uploads, revocation.
   Follow the `transfer_audit_events` (V030) conventions: no updates, no deletes, queries in
   `db/agent_auth.rs` or a sibling `db/agent_audit.rs`. Keep the event set small and mechanical;
   do not log request bodies or token material.

### Wallet (apps/identity-wallet)

4. **Claim approval screen.** Entry paths: manual code entry (user types the 6-digit `user_code`
   the agent displayed) and deep link from the `verification_uri`. The screen shows, before
   approval: agent registration type, issuer/subject identity where present, and the **exact
   scope list in human terms** (reuse the permission-set naming from the OAuth consent work).
   Approval is biometric-gated like PLC-op signing (`tauri-plugin-biometric`, existing pattern in
   the migration/recovery flows). Denial and expiry are explicit states, not silent.

5. **"My agents" screen.** Lists bound agents from `GET /v1/agents` with status
   (pending/claimed/revoked — status never by color alone, per DESIGN.md), scopes, last-used;
   per-agent detail view shows the audit trail; revoke is biometric-gated with a confirm step.

6. **Design compliance.** All UI through the Obsign token layer
   (`src/lib/styles/{tokens,fonts,base}.css`), primitives from `src/lib/components/ui/`,
   WCAG 2.2 AAA, no hex/px literals. Run `/impeccable` against the wallet brief for the new
   screens. IPC wrappers + types in `src/lib/ipc.ts` per existing conventions.

**Explicitly out of scope:** push notifications for pending claims (needs APNs infra); the
Custos MCP server (separate plan); operator-side (admin-companion) agent views; the anonymous
registration flow.

## Acceptance Criteria

### agent-consent.AC1: Claim ceremony
- **AC1.1:** An agent holding a valid `claim_token` can initiate a claim; the wallet-confirmed
  `user_code` flips the identity to `claimed`, after which assertion minting succeeds.
- **AC1.2:** Wrong or expired `user_code` fails closed with the spec error shape; attempts are
  rate-limited via the existing limiter infrastructure (this is a short-code guessing surface —
  same class as `transfer/accept`).
- **AC1.3:** Unconfirmed attempts expire and are swept; expired attempts cannot be confirmed.

### agent-consent.AC2: Management API
- **AC2.1:** `GET /v1/agents` returns only identities bound to the authenticated DID; account A
  cannot list or revoke account B's agents.
- **AC2.2:** Revocation immediately blocks new token exchanges (per the scope-enforcement plan's
  AC3.1) and is recorded in the audit log.

### agent-consent.AC3: Audit log
- **AC3.1:** Registration → claim → token exchange → a repo write → revocation produces the
  corresponding ordered audit events, each attributed to the right `registration_id`.
- **AC3.2:** The table accepts inserts only (no UPDATE/DELETE statements exist in the query
  layer); token material and request bodies never appear in `detail`.

### agent-consent.AC4: Wallet UX
- **AC4.1:** The approval screen displays scopes in plain language before biometric approval;
  approving with biometrics unavailable falls back per the existing biometric-gate pattern.
- **AC4.2:** "My agents" reflects revocation immediately and distinguishes
  pending/claimed/revoked with text + icon, not color alone.

## Implementation notes

- **Prerequisite:** the [agent scope-enforcement plan](2026-07-07-agent-scope-enforcement.md) —
  audit attribution rides on the `registration_id` token claim it introduces.
- New server routes need `.bru` files (`just bruno-check`); `/v1/agents*` are provisioning-style
  routes — follow `crates/pds/CLAUDE.md` for route/DB layering and the guard choice
  (`require_session` family, not admin guards).
- The Linear specs for MM-169/170 contain the exact request/response shapes — implement to those,
  and note that MM-169 (claim polling grant at the token endpoint) is how the *agent* learns the
  ceremony completed; it pairs naturally with this work but can land from its own ticket.
- Wallet state machine: mirror `claim.rs` (state in `AppState` behind a mutex, `_impl` test
  helpers, typed SCREAMING_SNAKE_CASE errors surfaced to the frontend).
