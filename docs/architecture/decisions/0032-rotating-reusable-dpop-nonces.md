# ADR-0032: Rotating, reusable DPoP nonces at the token endpoint

- **Status:** Accepted
- **Date:** 2026-08-18
- **Deciders:** malpercio
- **Related:** [docs/2026-08-03-oauth-interop-audit.md](../../2026-08-03-oauth-interop-audit.md)
  (gap 16 and the 2026-08-18 addendum), ADR-0031's sibling audit trail,
  `crates/pds/src/auth/dpop.rs`

## Context

RFC 9449 §8 lets an authorization server demand a server-issued nonce inside every DPoP
proof at the token endpoint, and leaves the nonce's lifecycle to the server. Custos
originally implemented the strictest reading: each nonce was 16 random bytes, stored in a
per-process map, and **consumed on first validation** — every token call needed a nonce no
other call had used.

The reference `@atproto/oauth-provider` does something much looser: the nonce is
`HMAC(secret, rotation_counter)` over a rotating window (`DPOP_NONCE_MAX_AGE` = 3 minutes,
rotating every minute, previous/current/next all accepted). Every caller in a window sees
the same nonce, reuse within the validity span is expected, and no state is kept at all.

The strict reading is not safer in practice — it is an interop trap. Clients are built and
tested against the reference, so an entire client-behavior class exists that single-use
nonces break and window nonces do not:

- concurrent token-endpoint calls holding the same cached nonce (multi-tab, background
  refresh, serverless fan-out) race; the loser gets `use_dpop_nonce`, and a failed retry
  can then burn the refresh-token rotation;
- serverless backends that cache one nonce per session across invocations work against
  bsky.social for minutes at a time but fail every call after the first against Custos.

The 2026-08-18 interop sweep observed exactly this signature in production (unretried
`use_dpop_nonce` 400s following a successful login; "logged in fine, every later call
500s"). The per-process map was also the worst entry on the audit's process-local-state
list: a restart invalidated every in-flight nonce dance, and horizontal scaling would have
broken correctness outright.

## Decision

We will mirror the reference scheme. The nonce is
`base64url(HMAC-SHA256(secret, unix_seconds / 60))`; validation accepts the previous,
current, and next windows and **never consumes anything**. The secret is derived from the
persistent JWT signing secret (V015) under a fixed domain-separation label, so nonces stay
consistent across restarts and across instances whenever that secret is persistent —
with no new table, config key, or migration.

## Consequences

- Clients cache and reuse a nonce for one to three minutes, matching what the reference
  taught them; concurrent calls no longer race each other's nonces.
- The store, its mutex, and its cleanup pass are gone. Nonce agreement across restarts and
  instances holds by construction — one process-local-state item from the audit's item 12
  retired for free.
- The replay bound at the token endpoint loosens from "single use" to "the nonce's validity
  span": a captured proof remains usable while its ±60s `iat` freshness window and an
  accepted nonce window overlap. This is precisely the reference provider's posture. Within
  that bound, authorization codes remain single-use; refresh tokens follow the existing
  reuse-grace policy — a superseded token is deliberately accepted again inside the ~60s
  concurrency grace window (minting another rotated pair), and reuse beyond it revokes the
  session family — so nonce reuse adds no replay surface beyond what that policy already
  accepts.
- Without `signing_key_master_key`, the JWT secret — and therefore the nonce secret — is
  per-boot. That degrades to the reference provider's own default (random per-boot secret),
  not below it.

## Alternatives considered

- **Keep single-use nonces.** Strictly stronger replay resistance on paper, but it is the
  documented cause of a real client class failing against us while working against the
  reference; "stricter than the ecosystem's reference" is indistinguishable from "broken"
  to a deployed client.
- **Single-use nonces stored in SQLite.** Fixes restart/multi-instance consistency but
  keeps the concurrency race that breaks real clients, and adds a write per token call.
- **A dedicated persisted nonce secret (new table or config).** More moving parts for no
  behavioral difference; the domain-separated derivation from the existing V015 secret has
  the same persistence properties with zero migration surface.
