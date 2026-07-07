# Custos MCP Server Design

## Summary

No MCP (Model Context Protocol) code exists anywhere in the repo, and no other ATProto PDS offers
a first-party, spec-clean way for an AI agent to onboard itself. Custos is uniquely positioned:
Wave 8's auth.md surface (agent registration, claim ceremony, JWT-bearer exchange) is exactly the
credential story MCP servers lack — most ship with static API keys pasted into config.

This plan builds `tools/mcp/` — a first-party MCP server ("Custos MCP") that authenticates to a
Custos PDS **through the auth.md flow itself**: discover (PRM → AS metadata → `auth.md`), register
(`POST /agent/identity`), wait out the human claim ceremony, exchange the service-signed assertion
for a scoped access token (JWT-bearer grant), then expose the PDS as MCP tools. It doubles as the
living end-to-end exercise of Wave 8 (complementing MM-177's server-side tests) and gives Wave 8 a
concrete finish line: the backlog endpoints become "whatever Custos MCP needs to run."

**Prerequisites (server-side, from the Wave 8 backlog):**
- MM-173 — JWT-bearer grant at `/oauth/token` (in review at time of writing).
- MM-169 — claim polling grant (`urn:workos:agent-auth:grant-type:claim`) so the MCP server can
  poll for ceremony completion.
- MM-170 — claim ceremony endpoint (covered by the
  [wallet consent & audit plan](2026-07-07-wallet-agent-consent-and-audit.md)).
- MM-176 — serve the `auth.md` discovery file at the service root (small; can be folded into
  this effort if unstarted).
- [Agent scope enforcement](2026-07-07-agent-scope-enforcement.md) — **hard prerequisite**; do
  not ship an agent-onboarding tool while agent tokens are full-access.

## Definition of Done

1. **Package.** `tools/mcp/` — Node/TypeScript, pnpm, mirroring `tools/interop/` conventions
   (that package already has ATProto client code, signing helpers in `crypto.js`, and a CLI
   harness to crib from). Ships as an MCP **stdio** server (the mode every MCP client supports);
   HTTP/SSE transport is out of scope for v1.

2. **auth.md onboarding flow**, run automatically on first launch against a configured PDS URL:
   - Discovery: fetch `/.well-known/oauth-protected-resource` → AS metadata → `GET /auth.md`.
   - Register via `POST /agent/identity`. **`service_auth` (email as `login_hint`) is the
     default and only out-of-the-box flow.** The `identity_assertion` flow is offered only when
     the operator has configured `[agent_auth] trusted_issuers` on the server *and* the MCP
     server is given an ID-JAG from one of those issuers via config; the trust-list validation
     itself is server-side (`routes/agent_identity.rs` verifies `iss` against the configured
     list) — the MCP server never decides trust, it just fails legibly when the server rejects
     an untrusted issuer.
   - Surface the `user_code` + `verification_uri` to the human (stderr + an MCP tool response),
     then poll the token endpoint with the claim grant until confirmed.
   - Exchange the resulting assertion via the JWT-bearer grant; cache tokens in an OS-appropriate
     location with `0600` perms; refresh/re-exchange transparently; on `access_denied`
     (revocation) fail with a clear "this agent was revoked in Obsign" message.

3. **Tool surface (v1 — deliberately small, matching the default agent scope profile):**
   - `whoami` — session/DID/handle/scope report (also the onboarding-status tool).
   - `create_post` — `app.bsky.feed.post` via `createRecord` (text, reply refs, optional image
     via `uploadBlob`).
   - `get_record` / `list_records` — read own repo by collection.
   - `put_record` / `delete_record` — gated behind a config flag (`allow_destructive`), off by
     default.
   - `search_timeline` — proxied appview reads (`app.bsky.feed.getTimeline`, `searchPosts`).
   - `account_status` — `checkAccountStatus` + storage/usage summary.
   Every tool's description states plainly that actions are attributed to the agent registration
   and visible in the user's audit log.

4. **Conformance role.** A `pnpm test` suite runs the onboarding flow against a local PDS
   (spawned the way `tools/interop` docs describe, or against staging with env creds) asserting
   each discovery/registration/claim/exchange step — this is the client half of MM-177.

5. **Docs.** `tools/mcp/README.md`: install, Claude Desktop / Claude Code MCP config snippets,
   the claim-ceremony walkthrough (screenshots deferred), scope profile explanation, and
   revocation behavior. Root `README.md` gets a one-paragraph pointer.

**Explicitly out of scope for v1:** HTTP/SSE transport and multi-user hosting; operator/admin
tools (separate idea, not approved); moderation actions; anything requiring `account:*` /
`identity:*` scopes; publishing to npm (revisit after the flow stabilizes).

## Acceptance Criteria

### custos-mcp.AC1: Self-onboarding
- **AC1.1:** Against a PDS with `[agent_auth]` enabled, first launch with only a PDS URL + email
  reaches the "waiting for claim" state and displays `user_code` + `verification_uri`.
- **AC1.2:** After the human confirms (wallet or the server-rendered page), polling completes and
  the server transitions to ready without restart.
- **AC1.3:** Against a PDS with agent auth disabled, the server reports the `*_not_enabled` error
  legibly and exits nonzero — no retry storm.

### custos-mcp.AC2: Tool behavior
- **AC2.1:** `create_post` produces a record visible via `getRecord` and (on a federated
  deployment) in the appview; the write appears in the agent audit log attributed to this
  registration.
- **AC2.2:** Tools requiring scopes outside the granted profile fail with the server's 403 relayed
  as a comprehensible MCP error, not a stack trace.
- **AC2.3:** With `allow_destructive` unset, `delete_record` is not offered in the tool list.

### custos-mcp.AC3: Credential hygiene
- **AC3.1:** Token cache file is `0600`; tokens never appear in logs or MCP responses.
- **AC3.2:** After revocation in the wallet, the next tool call fails with the revocation message
  and the server does not auto-re-register (re-registration requires explicit user action).

### custos-mcp.AC4: Conformance suite
- **AC4.1:** The test suite exercises discovery → register → claim → exchange → tool call and can
  run in CI against a locally spawned PDS.

## Implementation notes

- Read `bruno/agent_identity.bru` and `crates/pds/src/routes/agent_identity.rs` module docs for
  the exact registration contract; the Linear issues MM-169/173 contain the grant request/response
  shapes.
- Use the official `@modelcontextprotocol/sdk`; keep the ATProto/auth plumbing in modules shared
  with (or moved into a shared package alongside) `tools/interop` rather than duplicated.
- The claim-polling loop must honor `authorization_pending` + `slow_down` semantics
  (device-flow etiquette) with capped backoff.
- Sequencing: build against staging once MM-169/170/173/176 land; each missing server piece
  discovered here is a Wave 8 ticket, which is the point.
