# Agent Scope Enforcement Design

## Summary

The Wave 8 agent-identity plumbing (V037 schema, `POST /agent/identity`, `db/agent_auth.rs`,
`AgentAuthConfig`) stores per-identity `granted_scopes`, but the default — and only exercised —
value is `["com.atproto.access"]` (`crates/common/src/config.rs`, `default_agent_granted_scopes`).
When the pending token grants land (JWT-bearer, MM-173 in review; claim grant, MM-169), an agent
credential exchanged through them would functionally be a **full-access session**: everything the
user's own wallet can do, an agent can do. That contradicts the product thesis and gets harder to
fix once real agents hold tokens.

The PDS already has the right primitive: the granular OAuth scope grammar in
`crates/pds/src/auth/oauth_scopes.rs` (`repo:*`, `rpc:*`, `blob:*`, `account:*`, `identity:*`,
plus permission sets in `auth/permission_sets.rs`), enforced on OAuth-issued tokens. This plan
converges Wave 8 onto that grammar: agent registrations carry granular scopes end-to-end
(config → registration row → minted assertion → exchanged access token → per-route enforcement),
with a conservative default profile instead of `com.atproto.access`.

## Definition of Done

1. **Default agent scope profile.** `default_agent_granted_scopes()` changes from
   `["com.atproto.access"]` to a named conservative profile, e.g.
   `["repo:*?action=create&action=update", "rpc:app.bsky.*", "blob:*/*"]` — exact set to be
   settled during implementation against the grammar in `auth/oauth_scopes.rs`; the principle is
   **write-to-own-repo + appview reads, no account/identity/admin surface**. `account:*`,
   `identity:*`, app-password management, PLC-op signing, and provisioning routes are never
   reachable with agent-derived tokens unless explicitly configured.

2. **Scope threading.** The scopes stored on the `agent_identities` row at registration are the
   scopes embedded in the service-signed `identity_assertion` (already a claim), and the token
   endpoint grants (when they land / as part of this work if MM-173 has merged) copy them into the
   issued access token's scope claim — never widening, intersection-only if the exchange request
   asks for a subset.

3. **Enforcement parity.** Agent-derived access tokens flow through the **same** scope-check path
   as OAuth tokens (`auth/jwt.rs` scope validation + per-route requirements). No new parallel
   checker. If any route currently special-cases `com.atproto.access` as "full access", verify an
   agent token without that scope is correctly bounded.

4. **Distinguishability + revocation hook.** Agent-derived tokens carry `registration_id` (already
   a claim on the assertion) through to the access token, so: (a) `require_*` guards can expose it
   to handlers, (b) revoking an agent identity (`status = 'revoked'`) causes subsequent refresh /
   re-exchange to fail with `access_denied`, and (c) the audit plan
   ([wallet consent & audit](2026-07-07-wallet-agent-consent-and-audit.md)) can attribute actions.
   Live-token invalidation on revoke may be bounded by access-token TTL — document the TTL bound
   explicitly in `crates/pds/CLAUDE.md`.

5. **Config surface.** `[agent_auth] granted_scopes` remains operator-overridable; the docs
   comment in `config.rs` states the default profile and warns that adding `account:*` /
   `identity:*` hands agents account-lifecycle control.

**Explicitly out of scope:** per-agent (as opposed to per-deployment) scope selection UI — that is
the consent-screen plan's job; the anonymous registration flow (MM-242); scope UI in Obsign.

## Acceptance Criteria

### agent-scopes.AC1: Default profile is bounded
- **AC1.1:** A freshly registered agent identity's stored scopes equal the new default profile,
  not `com.atproto.access`.
- **AC1.2:** An access token derived from that identity can `createRecord` in the bound account's
  repo and proxy an `app.bsky.feed.getTimeline` read.
- **AC1.3:** The same token gets 403 (proper error envelope) on: `deactivateAccount`,
  `updateHandle`, `createAppPassword`, `sign_plc_operation`, and any `/v1/*` provisioning route.

### agent-scopes.AC2: No widening
- **AC2.1:** A token-exchange request asking for scopes beyond the registration's stored set is
  rejected or intersected (pick one, document it); the issued token never exceeds the stored set.
- **AC2.2:** Operator config narrowing `granted_scopes` narrows subsequently issued tokens without
  requiring re-registration.

### agent-scopes.AC3: Revocation
- **AC3.1:** After `status = 'revoked'`, exchange/refresh attempts fail with `access_denied`.
- **AC3.2:** `registration_id` is present on agent-derived access tokens and absent on ordinary
  session/OAuth tokens.

### agent-scopes.AC4: Regression safety
- **AC4.1:** Existing OAuth and session token flows are untouched: the full existing test suite
  passes with no behavioral diffs outside agent paths.

## Implementation notes

- Read `crates/pds/CLAUDE.md` route/DB rules first. Scope-check logic belongs in `auth/`, not in
  route handlers; handlers declare required scopes the same way OAuth-protected routes already do.
- The scope grammar and permission-set code shipped with MM-237
  (`docs/archive/design-plans/2026-07-05-oauth-scopes-permission-sets.md`) — read that archived
  plan for the grammar's semantics before choosing the default profile.
- If MM-173 (JWT-bearer grant) has merged by the time this is implemented, this plan modifies its
  issuance path; if not, land this as guardrails in the assertion-minting path
  (`routes/agent_identity.rs`) plus config, and note the token-endpoint obligation in the MM-173
  review.
- Any route behavior change (403s on newly bounded routes) needs corresponding `.bru`
  updates only if request/response shapes change; new tests are colocated `#[cfg(test)]`.
