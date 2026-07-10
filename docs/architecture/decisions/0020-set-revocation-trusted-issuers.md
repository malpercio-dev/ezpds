# ADR-0020: Provider-driven agent revocation via SETs, gated on the existing issuer trust list

- **Status:** Accepted
- **Date:** 2026-07-09
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0019](0019-authmd-agent-authentication.md) · [design plan](../../archive/design-plans/2026-07-09-agent-provider-revocation-set.md) · [test plan](../../archive/test-plans/2026-07-09-agent-provider-revocation-set.md) · MM-172 · PR #171 · `crates/pds/src/routes/agent_event.rs`

## Context

`identity_assertion` registrations are minted on a trusted issuer's word
(ADR-0019). When that provider offboards the user, decommissions the agent, or
loses a key, the PDS should stop honoring the registration promptly — not when
the operator happens to notice. RFC 8935 defines push delivery of Security
Event Tokens (RFC 8417) for exactly this. The non-obvious question isn't the
transport; it's the trust model: who may revoke, and does accepting inbound
revocations need its own opt-in?

## Decision

`POST /agent/event/notify` (the advertised `events_endpoint`) accepts RFC 8417
SETs pushed per RFC 8935. A SET is verified with the **same machinery as an
ID-JAG** — signature, `iss`, `aud` against `[agent_auth] trusted_issuers`
(`exp` only if present) — and there is **deliberately no separate opt-in
toggle**: the provider you trust to *vouch* for agents is exactly the party
you trust to *revoke* them. A SET carrying the
`…/agent/auth/identity/assertion/revoked` event type resolves the registration
by `(iss, sub)` and, in one transaction, flips it to `revoked` and writes an
audit event (`source = "provider_set"`). Delivery always answers `202`,
including for unknown or already-revoked subjects. Only `identity_assertion`
registrations are reachable — `service_auth` and `anonymous` have no
`(issuer, subject)` key and stay owner-revoked. There is no `jti` replay
store: revocation is idempotent, so a replayed SET is a no-op.

## Consequences

- A trusted provider can kill a compromised agent credential without operator
  action; the next assertion re-exchange returns `access_denied`, so live
  access ends within the 5-minute token TTL.
- Revocation authority is bundled with vouching authority. That's the point —
  but it means adding a `trusted_issuer` grants both powers at once, and
  operators should know that.
- Zero new config. A default deployment (empty trust list) refuses every SET;
  nothing is exposed until an operator deliberately trusts a provider.
- An unauthenticated caller can at most trigger one bounded signature check
  before rejection, covered by the existing global per-IP rate limiter.
- The error surface follows RFC 8935 (`{err, description}`), a third error
  envelope alongside XRPC and auth.md formats — confined to this endpoint.

## Alternatives considered

- **A separate opt-in toggle for inbound revocation.** Rejected: "Requiring a
  second opt-in would silently drop a trusted provider's revocation SETs — a
  security footgun" (design plan).
- **A `jti` dedup/replay store.** Unnecessary — the `status != 'revoked'`
  guard makes replay harmless, and a store would add state for no security
  gain.
- **RFC 8936 poll delivery, stream management, verification SETs.** Out of
  scope; one push-delivered event type is the whole contract, and it's the
  only one advertised in `events_supported`.
