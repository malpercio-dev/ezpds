# ADR-0019: Adopt the auth.md convention as the agent-authentication surface

- **Status:** Accepted
- **Date:** 2026-07-07 (work landed 2026-07-02 → 2026-07-09; backfilled 2026-07-10)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0016](0016-dynamic-lexicon-permission-set-resolution.md) · [Custos MCP plan](../../archive/design-plans/2026-07-07-custos-mcp-server.md) · [scope-enforcement plan](../../archive/design-plans/2026-07-07-agent-scope-enforcement.md) · [consent plan](../../archive/design-plans/2026-07-07-wallet-agent-consent-and-audit.md) · `crates/pds/assets/auth.md` · MM-169/170/171/173/176/177/242/245/247/248

## Context

v0.1's auth surface was built for humans: OAuth authorization-code with DPoP,
and app passwords. Wave 8 targets autonomous agents — MCP servers and similar
clients that need a credential without a browser session. The ecosystem's
answer today is a static API key pasted into config: invisible to the user,
unscoped, and unrevocable per-agent. That contradicts the product thesis —
the user sees and controls exactly what touches their identity. The choice:
treat agents as ordinary OAuth clients, invent a bespoke onboarding API, or
adopt WorkOS's emerging **auth.md** convention for agent self-onboarding.

## Decision

We implement the auth.md convention as a first-class PDS surface:

- **Discovery.** A served `GET /auth.md` skill document, plus an `agent_auth`
  block in the RFC 8414 AS metadata advertising the identity, claim, and
  events endpoints.
- **Self-registration.** `POST /agent/identity` with three registration types,
  every one **disabled by default**: `identity_assertion` (an ID-JAG from an
  issuer on the `[agent_auth] trusted_issuers` list), `service_auth`
  (email `login_hint`), and `anonymous` (ownerless pre-claim identity).
- **Human-in-the-loop claim.** Registrations bind to an account only through a
  device-flow-style ceremony: the agent shows a `user_code`, the human
  confirms at the `verification_uri` with their own credentials, and the agent
  polls the token endpoint with the `urn:workos:agent-auth:grant-type:claim`
  grant until confirmed.
- **Token exchange.** RFC 7523 `jwt-bearer` exchanges a service-signed
  `identity_assertion` for a 5-minute sender-unconstrained Bearer token — no
  DPoP, no refresh token; agents re-exchange with a fresh assertion.
- **Scopes.** Agent tokens flow through the same granular scope grammar and
  Lexicon permission-set resolution as OAuth tokens (ADR-0016) — no parallel
  checker. Granted scopes are clamped by intersection with the operator's
  `[agent_auth] granted_scopes` profile at every mint; the default profile is
  write-to-own-repo (create/update, not delete) plus blob upload — never
  `account:*`, `identity:*`, or `rpc:*`. Agent-derived tokens carry a
  `registration_id` claim, and sensitive routes refuse them
  (`require_not_agent`).

## Consequences

- ezpds gets a spec-clean, first-party agent onboarding story; the Custos MCP
  server self-onboards against it with zero static keys in config.
- Every agent credential is user-visible, user-claimed, and user-revocable
  (the wallet's consent + audit UI over `/v1/agents`).
- The 5-minute token TTL bounds revocation latency without token-introspection
  infrastructure; the cost is one re-exchange per 5 minutes per agent.
- A default deployment exposes nothing: all three registration types are
  opt-in, and an empty issuer trust list refuses every assertion.
- We commit to an external, still-evolving convention — WorkOS's grant URN,
  event schema URIs, and document format. If auth.md moves, we track it or
  fork it deliberately.
- Claim polling state is an in-memory tracker — consistent with the
  single-process SQLite relay, but a constraint on any future multi-process
  deployment.

## Alternatives considered

- **Agents as ordinary OAuth clients with static credentials.** What the MCP
  ecosystem ships today. No self-registration, no human claim gate, no
  per-agent revocation; exactly the model the product exists to replace.
- **Full-access agent sessions.** The first cut stored
  `["com.atproto.access"]` — an exchanged agent credential "would functionally
  be a full-access session … that contradicts the product thesis and gets
  harder to fix once real agents hold tokens" (scope-enforcement plan). Scope
  clamping shipped before the onboarding tool did, as a hard prerequisite.
- **A bespoke onboarding API.** No discovery story: every agent framework
  would need a custom Custos integration. auth.md gives any agent a served
  document telling it how to onboard.
- **A parallel agent scope checker.** Rejected in favor of converging on the
  existing grammar (ADR-0016) — one enforcement path, one place to audit.
