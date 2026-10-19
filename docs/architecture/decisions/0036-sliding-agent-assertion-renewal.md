# ADR-0036: Sliding assertion renewal for confirmed agent bindings

- **Status:** Accepted
- **Date:** 2026-08-29
- **Deciders:** malpercio
- **Related:** MM-544; ADR-0019 (auth.md agent authentication); `crates/pds/src/routes/oauth_token/jwt_bearer.rs`, `crates/common/src/config.rs` (`[agent_auth] claimed_assertion_ttl_secs`), `tools/mcp/src/auth.ts`

## Context

The auth.md flow issues an agent two credentials: a 5-minute Bearer access token
(renewable via the jwt-bearer grant) and the service-signed `identity_assertion` it
renews from. The assertion originally lived `[agent_auth] assertion_ttl_secs` — one
hour — for *every* binding, claimed or not. The short lifetime was meant to bound
stolen-assertion exposure.

In practice it bounded legitimate use instead. An agent that acts sporadically — a
few posts a week — found its assertion expired in every action window, and the only
recovery was a full re-registration plus a fresh claim ceremony with a human
`user_code` confirmation. The human gate that was designed to confirm a binding
*once* became a recurring toll on every quiet agent. Sovereign child agents had the
same failure with a partial patch: a parent-driven re-mint route
(`POST /agent/child/assertion`), which still needs the human parent.

Meanwhile the actual security backstop for a confirmed binding was never the
assertion's expiry: the jwt-bearer grant checks the identity row's state on every
exchange, so flipping a registration to `revoked` closes the credential within one
access-token lifetime regardless of how long the assertion would otherwise live.

## Decision

We will treat a confirmed binding's assertion as a renewable credential, the way
OAuth treats a refresh token, with two changes:

1. **TTL split.** Assertions minted for *confirmed* bindings — the claim-ceremony
   confirm, the re-mint for an already-claimed `(iss, sub)`, sovereign-child
   capabilities and their renewals — live `[agent_auth] claimed_assertion_ttl_secs`
   (default 30 days). The 1-hour `assertion_ttl_secs` now governs only the
   pre-claim (anonymous) assertion, where no human has confirmed anything yet.

2. **Sliding renewal.** Every successful jwt-bearer exchange re-mints the
   assertion — the row's stored grant clamped to the operator's *current*
   `granted_scopes` — persists it, and returns it in the response
   (`identity_assertion` + `assertion_expires`, the claim-polling field names).
   An agent that persists the renewal only ever expires after a full claimed-TTL
   of total inactivity. The first-party MCP client persists it automatically.

The renewal and the exchange's audit row commit in one transaction, and both fail
closed: no token leaves the building without landing on the audit trail.

## Consequences

- Sporadic agents work: the claim ceremony runs once per binding, not once per
  assertion lifetime. Only a binding dormant past `claimed_assertion_ttl_secs`
  needs a new ceremony.
- A stolen claimed assertion is now durable until revoked, exactly like a stolen
  OAuth refresh token. Revocation — owner or operator, `/v1/agents/.../revoke` —
  remains the kill switch and is unweakened: it is enforced at every exchange.
  Operators wanting the old posture can set `claimed_assertion_ttl_secs = 3600`.
- Narrowing `[agent_auth] granted_scopes` still narrows every subsequent renewal
  without re-registration, because the re-mint clamps to current config.
- Old assertions are not invalidated by a renewal (there is no per-`jti` revocation
  list); several minted assertions for one binding may be live at once, bounded by
  their own expiries. This matches the pre-existing re-mint paths.

## Alternatives considered

- **Longer TTL only, no renewal.** Fixes the weekly-posting agent but re-imposes a
  ceremony every N days even on continuously active agents. The renewal costs one
  UPDATE per exchange and removes the cliff entirely.
- **Renewal only, keeping the 1-hour TTL.** Fails the actual reported scenario: an
  agent acting twice a week is dormant longer than any renewal window an hour long.
- **A dedicated refresh grant or endpoint.** More surface for the same capability
  the existing exchange already proves possession for; every client would need a
  second code path. Folding the renewal into the exchange response is additive and
  backward-compatible (clients that ignore the new fields behave as before).
- **Refresh tokens for agents.** Would bolt the OAuth refresh-token machinery
  (rotation, DPoP binding decisions, storage) onto a flow whose assertion already
  fills that role; the assertion *becoming* refresh-token-like is the smaller step.
